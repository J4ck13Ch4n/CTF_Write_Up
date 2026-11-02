# FLARE-On 13 — Challenge 9: NeonOutRun

> *"A taste of my torment for everyone."* — một trong 14 câu mà ma trận chữ của game tự dựng.

## Tổng quan

`neon_outrun` là một **app Tauri 2.0** (Rust + webview), chạy game đua xe "OutRun" trên
Canvas 2D. Nhưng toàn bộ *game logic* không nằm ở frontend: backend Rust **nhúng cả V8**
(`rusty_v8 0.32.1`) và compile một script tên `backend.js` vào đó.

| Tầng | Thành phần |
|---|---|
| Frontend | `index.html` + game đua xe (Canvas 2D), nằm trong `frontend_min/` |
| IPC bridge | Tauri command `plugin:neon\|e` — JS ↔ Rust |
| Native backend | ELF x86-64 PIE 21.2 MB, `tauri-2.11.5` + `rusty_v8-0.32.1`, worker thread stack **8 MiB** |
| Packed script | `backend.js` **4.229 byte**, *không tồn tại* cho tới khi 4 lớp decode chạy |
| Native hooks | **3 `FunctionCallback` của V8** được cài lên context *trước khi* script được compile |
| Game logic | **28 lap** với 28 "split time" — chỗ có flag |

Bí mật nằm ở tầng native: **V8 builtin bị thay**. `backend.js` nhìn bình thường, chạy đúng,
và tự dựng ra một chuỗi trông rất giống flag — nhưng đó là **decoy**.

*(Các lệnh `python3` dưới đây giả sử đã kích hoạt venv: `source ../.venv/bin/activate` —
xem README mục "Môi trường".)*

```
$ 7z x -y -pflare -o9 9-NeonOutRun.7z
$ cd 9 && file neon_outrun
neon_outrun: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, stripped
```

Máy challenge **không có** `libwebkit2gtk-4.1.so.0` / `libsoup-3.0.so.0`, nên app **không chạy
được** → phải giải tĩnh + emulate.

## Bản đồ giải quyết

```
neon_outrun (ELF PIE, stripped)
  │
  ├─ .rodata @ 0x21db73  ──►  blob "backend.js" đã đóng gói
  │      │
  │      ├─ L1  XOR 2 byte  d3 / 5a
  │      ├─ L2  custom LZSS (window 4096, offset 12 bit, len 4 bit)
  │      ├─ L3  Zstandard frame  (magic 28 b5 2f fd)  →  1.717 byte raw DEFLATE
  │      └─ L4  raw DEFLATE (RFC1951, KHÔNG có zlib header/adler32) → 4.229 byte JS
  │
  └─ .text @ 0x67xxxx   ──►  3 V8 builtin bị thay bằng code Rust
         │
         ├─ 0x67deb2  Array.prototype.sort        → acc1 = Σ |split|·scale
         │                                          (MMIX LCG 0x5851f42d4c957f2d / 0x14057b7ef767814f)
         ├─ 0x67eb83  Math.min                     → acc2 += v·sin(θ)
         │      θ = (π/180)·(p_i + s_i·b)            p_i, s_i ← 2 máy trạng thái 128-bit
         │      b  = clamp(floor(lap_secs),0,255)    ← byte ghi vào vector 28 byte
         └─ 0x67e81e  String.prototype.replaceAll  → |acc1-acc2| < 1e-6 ?
                ghi đè 28 byte đầu bằng vector lap-time
                string[30] += 0x3b          ('1' → 'l')

  ⇒ 28 đồng dư  p_i + s_i·b_i ≡ 90 (mod 360)  ⇒ 28 byte flag
```

## 1. Triage: đây là app Tauri 2 + V8 nhúng

```bash
$ strings -t x neon_outrun | grep -E "tauri-2|rusty_v8|frontend_min|8MiB"
 11024a .cargo/registry/src/index.crates.io-.../tauri-utils-2.9.3/src/platform.rs
 12257a .cargo/registry/src/index.crates.io-.../rusty_v8-0.32.1/src/context.rs
 135c9a .cargo/registry/src/index.crates.io-.../rusty_v8-0.32.1/src/isolate_create_params.rs
 1c7d20 unable to create thread with 8MiB stack
 1c7d7e neon_outrun0.1.0com.neon.outrunNeon OutRun../frontend_min

$ strings -t x neon_outrun | grep -n "plugin:neon"
 1ca0d9 plugin:menu|set_enabled...plugin:neon|eplugin:path|basename...
```

`tauri.conf.json` được nhúng trực tiếp ở `0x1c7d7e`:
`{"productName":"Neon OutRun","version":"0.1.0","identifier":"com.neon.outrun","frontendDist":"../frontend_min"}`.

**Điểm mấu chốt:** `rusty_v8` ⇒ backend Rust tự tạo một V8 isolate và chạy script trong đó.
Script đó phải được giải mã trước, và **3 builtin của V8 bị thay bằng code native**.

## 2. Tìm & giải 4 lớp packing của `backend.js`

### 2.1 Nhận diện blob

`backend.js` không tồn tại dưới dạng plaintext trong ELF (grep `currentLap`,
`bestLapSeconds`, `getContext` → 0 kết quả). Nhưng blob **đã đóng gói** thì vẫn nằm trong
`.rodata`. Mấu chốt: blob được XOR bằng key 2 byte `d3 5a`, nên **magic zstd `28 b5 2f fd`**
chỉ xuất hiện ở dạng đã XOR:

```bash
$ python3 - <<'EOF'
import re
d = open('neon_outrun','rb').read()
magic = bytes.fromhex('28b52ffd')
for key in [(0xd3,0x5a),(0x5a,0xd3)]:
    for pat in (bytes(x^key[i%2] for i,x in enumerate(magic)),
                bytes(x^key[0] for x in magic),
                bytes(x^key[1] for x in magic)):
        hits=[m.start() for m in re.finditer(re.escape(pat), d)]
        if hits: print(key, pat.hex(), [hex(h) for h in hits])
EOF
(90, 211) 7266752e ['0x21db74']
```

⇒ **đúng một chỗ duy nhất** trong cả 21 MB. Blob bắt đầu ngay trước đó, ở `0x21db73`, ngay
sau chuỗi snapshot của V8 `"FromUtf8Errorbyteserrorcapacity overflow,"`.

### 2.2 Bốn lớp

| Lớp | Encoding | Dấu hiệu đúng | Byte đầu sau khi giải |
|---|---|---|---|
| **1** | XOR 2 byte `d3 5a` | byte đầu **trong file** không phải header container hợp lệ (XOR chưa gỡ) | `ff 28 b5 2f fd 00 68 a9 35 ...` |
| **2** | Custom LZSS (window 4096, offset 12 bit, len 4 bit) | **xuất hiện magic `28 b5 2f fd`** | `28 b5 2f fd 00 68 a9 35 ...` |
| **3** | **Zstandard frame** (magic LE `0xFD2FB528`) | output **không có** zlib header ⇒ phải là raw deflate | `28 b5 2f fd 00 68 a9 35 00 ad ...` |
| **4** | **Raw DEFLATE** (`miniz_oxide`) | ra đúng **4.229 byte** JavaScript | `let neon="";let carInitialY=0.8;...` |

Định dạng LZSS lớp 2 (đọc từ asm `0x68a453`):

```asm
68a465: movzbl (%r15,%rbp,1),%ecx     ; a = tok[0]
68a471: movzbl (%r15,%rax,1),%ebx    ; b = tok[1]
68a478: shl    $0x4,%eax
68a47b: and    $0xf00,%eax            ; offset = ((b & 0xF0) << 4) | a   (12 bit)
68a483: and    $0xf,%ebx             ; len   = (b & 0x0F) + base
```

Một byte điều khiển mang 8 flag (bit LSB trước): flag = 1 → 1 byte literal, flag = 0 → token
khớp 2 byte.

**Bằng chứng "raw deflate chứ không phải zlib":** sau lớp 3 ta được 1.717 byte bắt đầu bằng
`28 b5 2f fd`; nếu đây là zlib stream thì byte đầu phải là `78 01`/`78 9c` và cuối phải có
Adler-32. `zlib.decompress(data)` **thất bại**, còn `zlib.decompressobj(-15)` (RFC 1951 thô)
thì thành công.

```bash
$ python3 scripts/unpack_backend.py
[*] ELF            : .../neon_outrun (21183560 bytes)
[*] packed blob    : file offset 0x21db73 (xor phase 1)
[L1] XOR d3/5a      : ff28b52ffd0068a935ff00ad576d6fe3 ...
[L2] LZSS           : 1765 bytes, starts with 28b52ffd0068a935
[L3] zstd           : frame 1726 bytes -> 1717 bytes of raw deflate
     zstd frame hdr : 28b52ffd0068a93500ad
     (no 78 01/78 9c zlib header, no adler32 -> raw RFC1951)
[L4] raw inflate    : 4229 bytes of JavaScript
[+] written .../work/backend.js (4229 bytes)
[+] node --check    : OK
```

## 3. `backend.js` và cái bẫy decoy

```javascript
function generateLaps(){
  laps=[];let splits=[];
  for(let i=0;i<27;i++){ splits.push(Math.round(-1000-Math.random()*98000)); }
  splits.push(-100000);
  splits.sort((a,b)=>b-a);                       // ← hook #1  (Array.prototype.sort)
  ...
}
...
      let lapSecs=(now-state.lapStartTime)/1000;
      state.bestLapSeconds=Math.min(state.bestLapSeconds,lapSecs);   // ← hook #2  (Math.min)
      ...
      neon+=messages[Math.floor((state.currentLap-1)/2)][map[state.currentLap-1]];
      ...
        neon+=String.fromCharCode(64,102,49,97,114,101,45,111,110,46,99,111,109);
        state.finished=true;
        state.neon=neon.replaceAll(" ","_");                          // ← hook #3
```

`String.fromCharCode(64,102,49,…)` = `"@f1are-on.com"` — chữ **`1`** (số một) thay cho chữ
**`l`**. Domain viết sai *có chủ đích*: nó đọc như một mệnh lệnh **"decode this system to win
it"**.

Chuỗi decoy mà JS tự dựng (tính lại từ `messages[]` + `map[]`):

```
decode this system to win it@f1are-on.com        (41 ký tự, có 5 khoảng trắng)
```

Nếu ta chỉ phân tích `backend.js` thì ta sẽ nộp domain sai. **Flag không nằm ở tầng JS.**

## 4. Ba native hook: đọc trong ELF

Các tên property cũng bị obfuscate: chúng được XOR-decoded lúc runtime (3 mảng byte ở
`0x6891a5`, `0x689396`, `0x689708`).

```bash
$ python3 - <<'EOF'
for enc, key in (("8123fe456160493eda52","f3468e2900032c7fb63e"),
                 ("efb5336e","a2d44706"),
                 ("66f698eaf4","2784ea8b8d")):
    print(bytes(a^b for a,b in zip(bytes.fromhex(enc),bytes.fromhex(key))).decode())
EOF
replaceAll
Math
Array
```

Ba callback được đăng ký ở `0x689334` / `0x6896ac` / `0x689b0a`:

```bash
$ objdump -d neon_outrun | grep -E "67deb2|67eb83|67e81e"
 484091:  689334: lea -0xab1d(%rip),%rax   # 67e81e   (replaceAll)
 484324:  6896ac: lea -0xab30(%rip),%rax   # 67eb83   (min)
 484619:  689b0a: lea -0xbc5f(%rip),%rax   # 67deb2   (sort)
```

### 4.1 `Array.prototype.sort` @ `0x67deb2` — tạo `acc1`

```asm
67dfac: movabs $0x5851f42d4c957f2d,%rcx      ; MMIX LCG
67dfb6: imul   %rax,%rcx
67dfba: movabs $0x14057b7ef767814f,%rax
67dfc4: add    %rcx,%rax                     ; state = state*A + C
67dfd4: mov    %rax,%fs:0xffffffffffffff68   ; lưu state (TLS)
...
67e09b: movapd %xmm0,%xmm1
67e09f: cmpordsd %xmm0,%xmm1
67e0a4: andpd  %xmm0,%xmm1                  ; |x_i|
67e0a8: mulsd  0x10(%rsp),%xmm1             ; × scale
67e0ae: movsd  %xmm1,(%r14,%r15,8)
...
67e241: movsd  0x1081e0,%xmm0               ; acc1 = -0.0 + Σ |x_i|·scale
```

State LCG khởi tạo tại `0x67e4ac`: `movabs $0x123456789abcdef0` → `fs:-0x98`. Hook này **không**
gọi `sort` của V8 nữa mà tự tính `acc1 = scale·Σ|split_i|` và đổ bản sao `(|split|·scale)` vào
một `Vec<f64>` tĩnh (đây chính là nguồn `v_i` mà hook `min` sẽ pop).

### 4.2 `Math.min` @ `0x67eb83` — tạo `acc2` (trái tim của challenge)

```asm
67eec7: movzbl %al,%esi          ; k  (byte hằng, sinh ra từ 1 CFF 8-bit)
67eeca: mov   %r14d,%edi          ; chỉ số lap
67eecd: call  67f9d8             ; máy trạng thái #1  -> u64
67eed2: movzbl %al,%edi
67eed5: call  68003e             ; máy trạng thái #2  -> u64 + byte dấu
67eeda: mov   %rax,0x28(%rsp)     ; p_i
67eedf: mov   %dl,0x7(%rsp)      ; byte dấu (bit0 = 1 => đảo dấu)
...
67eee9: call  *0x1424058         ; f64::floor
67eef3: maxsd  %xmm0,%xmm2       ; max(0, floor(lap_secs))
67eef7: movsd  0x1089c0,%xmm1    ; 255.0
67eeff: minsd  %xmm2,%xmm1       ; min(255, ...)
67ef03: cvttsd2si %xmm1,%eax     ; b = byte lap-time
67ef67: call  687d50             ; đẩy b vào Vec<u8> (28 byte)
...
67f8b8: testb $0x1,0x7(%rsp)     ; dấu
67f8c7: xorpd  %xmm1,%xmm0       ; xmm0 = ±b
67f8cb: cvtsi2sdq 0x28(%rsp),%xmm3 ; xmm3 = (double)p_i
67f8f8: addsd  %xmm0,%xmm3       ; xmm3 = p_i + s·b
67f910: movsd  0x108aa8,%xmm0    ; π
67f918: divsd  %xmm2,%xmm0       ; π / M     (M == 180)
67f91c: mulsd  %xmm3,%xmm0       ; θ = (π/180)(p_i + s_i·b)
67f92e: call  *0x1423370         ; f64::trunc  (rút gọn θ về (-2π, 2π))
67f953: call  687cff             ; sin(θ) bằng chuỗi Taylor 16 số hạng
...
67f991: mulsd  0x8(%rsp),%xmm0   ; v_i · sin(θ)
67f99c: addsd  0x8(%rdi),%xmm0   ; acc2 += …
```

`M` là **hằng số 180** (emulator đọc được trực tiếp từ thanh ghi `r9`). `sin` được tính bằng
**chuỗi Taylor 16 số hạng** (`sub_687d80` + `sub_687cff`), sai số < 1e-16 ⇒ không ảnh hưởng
điều kiện 1e-6.

### 4.3 `String.prototype.replaceAll` @ `0x67e81e` — kiểm tra & ghi flag

```asm
67e972: ucomisd 0x107e28,%xmm1     ; |acc1|  so với 1e-6
67e984: ucomisd 0x107e28,%xmm1     ; |acc2|  so với 1e-6
67e98e: subsd   %xmm3,%xmm2        ; acc1 - acc2
67e996: movsd   0x107e28,%xmm0     ; 1e-6
...
67ea47: movzbl  (%r14,%r9,1),%r10b ; lấy byte thứ i của vector lap-time
67ea4b: mov     %r10b,(%rcx,%r9,1); ghi đè lên string[i]
...
67ea62: cmp     $0x1f,%rdx         ; độ dài string >= 31 ?
67ea68: addb    $0x3b,0x1e(%rcx)  ; string[30] += 0x3b
```

Tức là: **nếu** `|acc1 − acc2| < 1e-6` (và cả hai khác 0) thì hook **ghi đè 28 byte đầu** chuỗi
victory bằng 28 byte lap-time, rồi **cộng `0x3b`** vào byte ở index **30**. Index 30 của chuỗi
decoy chính là chữ `'1'` trong `@f1are-on.com` ⇒ `0x31 + 0x3b = 0x6c = 'l'` ⇒ `@flare-on.com`.

## 5. Điều kiện thắng ⇒ 28 đồng dư độc lập

* `sort` hook: `acc1 = Σ_i v_i` với `v_i = scale·|split_i|`.
* `min` hook: `acc2 = Σ_i v_i · sin(θ_i)` (cùng bộ `v_i`, lấy từ `Vec<f64>` mà sort hook đã điền).

Điều kiện thắng:

$$\Big|\sum_{i=0}^{27} v_i\big(1-\sin\theta_i\big)\Big| < 10^{-6}$$

Vì `v_i > 0` và `sin θ_i ≤ 1`, tổng chỉ có thể gần 0 khi **từng số hạng** gần 0:

$$\sin\theta_i = 1 \iff \theta_i \equiv 90^\circ \pmod{360^\circ}$$

Với `θ_i = (π/180)(p_i + s_i·b_i)`:

$$\boxed{\,p_i + s_i b_i \equiv 90 \pmod{360}\,}$$

Suy ra byte lap-time:

$$b_i=\begin{cases}(90-p_i)\bmod 360 & s_i=+1\\ (p_i-90)\bmod 360 & s_i=-1\end{cases}$$

## 6. Emulate 2 máy trạng thái 128-bit

Hai máy trạng thái nằm trong hai hàm CFF (control-flow-flattened) của chính backend Rust:

* `sub_67f9d8(idx: u8, k: u8) -> u64` — máy #1 (byte-scrambler), *chỉ số theo lap*;
* `sub_68003e(k: u32) -> u64` — máy #2 (LCG 128-bit: `v5`/`v7`, có carry).

Cả hai đều là hàm thuần của đối số nên **không cần viết lại thuật toán** — ta **emulate chính mã
máy của ELF bằng Unicorn** (`scripts/emulate_native.py`):

```python
elf = Elf(ELF)
emu = MinHookEmu(elf)              # nạp segment, áp relocation R_X86_64_RELATIVE
r   = emu.run_lap(lap_index, lap_secs)
#  -> r["p"]     : p_i  (u64, đọc từ 0x28(rsp))
#  -> r["byte"]  : byte dấu (0x7(rsp)), bit0 = 1 => s_i = -1
#  -> r["M"]     : 180
#  -> r["acc"]   : acc2 tăng thêm trong 1 lap (để kiểm chứng sin(θ)=1)
```

Các lệnh gọi V8 (`67e4f2`, `6f6550`, `61818c`, `604a82`, `69c4a0`, `687d50`, …) được **stub** bằng
trampoline tự viết; `floor`/`trunc`/`sin` chạy **mã thật** của ELF.

Kết quả 28 cặp `(p_i, s_i)` (cột `chr` bị lược bỏ — tự quy đổi `chr(b_i)`):

| # | p_i (signed 64-bit) | p_i mod 360 | s_i | b_i |
|---|---------------------|-------------|-----|-----|
|  0 |             168236812 | 172 | -1 |  82 |
|  1 |            -352168521 |  39 | +1 |  51 |
|  2 |             105161035 | 355 | +1 |  95 |
|  3 |            -339661807 | 353 | +1 |  97 |
|  4 |             325269707 | 347 | +1 | 103 |
|  5 |              44245479 |  39 | +1 |  51 |
|  6 |            -115497520 | 200 | -1 | 110 |
|  7 |             -14004874 | 206 | -1 | 116 |
|  8 |             142547035 | 355 | +1 |  95 |
|  9 |             187501462 | 142 | -1 |  52 |
| 10 |            -330601852 | 188 | -1 |  98 |
| 11 |             236980938 | 138 | -1 |  48 |
| 12 |            -204813027 | 333 | +1 | 117 |
| 13 |             278825606 | 206 | -1 | 116 |
| 14 |             101465275 | 355 | +1 |  95 |
| 15 |            -260863714 | 206 | -1 | 116 |
| 16 |             269043978 | 138 | -1 |  48 |
| 17 |             280216795 | 355 | +1 |  95 |
| 18 |            -300065568 | 192 | -1 | 102 |
| 19 |              25169079 |  39 | +1 |  51 |
| 20 |             -28832361 |  39 | +1 |  51 |
| 21 |            -195638562 | 198 | -1 | 108 |
| 22 |              89275315 | 355 | +1 |  95 |
| 23 |             309872710 | 190 | -1 | 100 |
| 24 |              79102841 |  41 | +1 |  49 |
| 25 |             -62925628 | 212 | -1 | 122 |
| 26 |             352786172 | 212 | -1 | 122 |
| 27 |            -355333351 | 329 | +1 | 121 |

**Tự kiểm chứng:** chạy lại hook với `lap_secs = b_i` ⇒ đóng góp của lap đó vào `acc2` đúng
bằng `1.0` (tức `sin θ_i = 1`), trong khi `lap_secs = 51` cho `0.857…` và `lap_secs = 142` cho
`0.5`:

```
      lap  0  b= 82 ? acc2 contribution=1  OK
      lap  1  b= 51 ? acc2 contribution=1  OK
      ...
      lap 27  b=121 ? acc2 contribution=1  OK
```

## 7. Lời giải

```
decoy (JS)        : decode this system to win it@f1are-on.com
ghi đè 28 byte đầu: <28 byte flag>@f1are-on.com
string[30] += 0x3b: '1' -> 'l'
FLAG              : <FLAG>
```

```bash
$ python3 scripts/solve.py
...
--- D) assemble the flag -----------------------------------------
[*] after the 28 byte overwrite : '<FLAG>'
[*] byte[30] += 0x3b           : '1' -> 'l'

==========================================================================
FLAG: <FLAG>
==========================================================================
```

Chuỗi decoy dài 41 ký tự (`'@'` ở index 28, `'f'` 29, `'1'` 30) và **5 khoảng trắng** nằm trong
28 ký tự đầu — nên sau khi hook ghi đè, chuỗi không còn khoảng trắng nào (hook `replaceAll`
không thực sự thay khoảng trắng nữa, nó làm việc khác đi).

## 8. Bài học

1. **"Chạy được" không đồng nghĩa với "đọc được".** Ở đây app không chạy được (thiếu
   `libwebkit2gtk-4.1`), nhưng phần cần thiết — decoder 4 lớp + hook — lại là *pure
   computation*. Emulate mã máy bằng Unicorn đáng giá hơn nhiều so với viết lại thuật toán bị
   control-flow-flattening.
2. **Tìm container header trong dữ liệu đã mã hoá.** Blob XOR 2 byte ⇒ magic zstd chỉ xuất
   hiện ở dạng XOR; grep theo mẫu XOR cho ra **đúng một** hit trong 21 MB ⇒ vị trí blob được
   xác định chắc chắn.
3. **"Thiếu zlib header" là bằng chứng, không phải phỏng đoán.** RFC 1950 có 2 byte header +
   Adler-32; thiếu chúng ⇒ phải dùng RFC 1951 thô (`wbits = -15`).
4. **Builtin của runtime là vũ khí.** `Array.prototype.sort`, `Math.min`,
   `String.prototype.replaceAll` bị thay trước khi script compile ⇒ đọc script thuần **không
   bao giờ** thấy flag. Luôn kiểm tra "có ai đó patch runtime không?".
5. **Tách bạch "chuỗi trông giống flag" và "flag".** `@f1are-on.com` sai đúng 1 byte — đó là
   *chỉ thị* ("decode this system to win it"), không phải mồi nhử ngẫu nhiên.
6. **Điều kiện thắng dạng tổng các số hạng không âm ⇒ tách được thành các hệ độc lập.**
   `Σ v_i(1 − sin θ_i) = 0` với `v_i > 0` ⇒ mỗi `sin θ_i = 1` ⇒ 28 phương trình đồng dư độc
   lập, mỗi cái giải được bằng modular arithmetic.
7. **Tự kiểm chứng kết quả bằng chính binary.** Sau khi suy ra `b_i`, ta chạy lại hook với
   `lap_secs = b_i` và xác nhận đóng góp vào `acc2` đúng bằng `1.0` — bằng chứng máy-mó rằng
   nghiệm thỏa đúng điều kiện thắng, không chỉ "ra một chuỗi đẹp".

## Flag

```
R3_ag3nt_4b0ut_t0_f33l_d1zzy@flare-on.com
```
