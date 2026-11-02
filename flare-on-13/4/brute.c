#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <pthread.h>
typedef void (__attribute__((ms_abi)) *kfn)(uint32_t, uint32_t, uint8_t*);
static uint8_t *IMG; static kfn F; static const uint8_t *CT; static int NT;
static void rc4(const uint8_t *k,int kl,const uint8_t *in,uint8_t *out,int n){
  uint8_t S[256]; for(int i=0;i<256;i++)S[i]=i;
  int j=0; for(int i=0;i<256;i++){j=(j+S[i]+k[i%kl])&255; uint8_t t=S[i];S[i]=S[j];S[j]=t;}
  int i=0; j=0; for(int x=0;x<n;x++){i=(i+1)&255;j=(j+S[i])&255;uint8_t t=S[i];S[i]=S[j];S[j]=t;out[x]=in[x]^S[(S[i]+S[j])&255];}
}
static void *work(void *arg){
  long id=(long)arg; uint8_t h[32],pt[64];
  for(uint64_t s=id;s<=0xffffffffULL;s+=NT){
    F((uint32_t)s,0xb501e7e,h);
    rc4(h,16,CT,pt,0x33);
    int ok=1; for(int x=0;x<0x33;x++){ if(pt[x]<0x20||pt[x]>0x7e){ok=0;break;} }
    if(ok){ pt[0x33]=0; printf("serial=%08llx flag=%s\n",(unsigned long long)s,pt); fflush(stdout);}
  }
  return 0;
}
int main(int argc,char**argv){
  FILE*f=fopen("img.bin","rb"); fseek(f,0,2); long n=ftell(f); fseek(f,0,0);
  IMG=mmap((void*)0x140000000,(n+0xfff)&~0xfff,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0);
  fread(IMG,1,n,f); fclose(f);
  F=(kfn)0x140134ca0; CT=(uint8_t*)0x1401bd3b0; NT=argc>1?atoi(argv[1]):20;
  uint8_t h[32]; F(0x12345678,0xb501e7e,h); for(int i=0;i<32;i++)printf("%02x",h[i]); printf("\n"); fflush(stdout);
  if(argc>2) return 0;
  pthread_t t[64]; for(long i=0;i<NT;i++)pthread_create(&t[i],0,work,(void*)i);
  for(int i=0;i<NT;i++)pthread_join(t[i],0);
  puts("done");
}
