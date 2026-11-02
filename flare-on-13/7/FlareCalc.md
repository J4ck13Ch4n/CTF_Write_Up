# FLARE-On 13 — Challenge 7: FlareCalc

> *"…one calculator, one certificate, and a very long way down."*

## Tổng quan

`7-FlareCalc.7z` (mật khẩu `flare`) chỉ chứa **1 file**:

| File | Kích thước | Mô tả |
|---|---|---|
| `FlareCalc.exe` | 1.507.488 | PE32+ x64 GUI (`Flare-On Calculator`), overlay Authenticode 529.568 byte |

Archive không có README; mật khẩu master chỉ xuất hiện trong description của challenge
(`8675309-88224646-31428571` — 8675309 là số "Jenny" kiểu Tommy Tutone, 31428571 = π xấp xỉ 22/7).

*(Các lệnh `python3` dưới đây giả sử đã kích hoạt venv: `source ../.venv/bin/activate` —
xem README mục "Môi trường".)*

File exe là một cái máy tính chạy thật, nhưng **không có đoạn code nào đọc overlay** của nó.
Toàn bộ bí mật nằm trong phần "chữ ký số" ở cuối file: bên trong là 1.035 record ASN.1
trong chứng thư X.509 giả, và 1.033 record đó là **stub x86-64** — tức là **node của một DFA**.

```
$ 7z x -y -pflare -o7 7-FlareCalc.7z
$ cd 7 && python3 -c "
import pefile
p = pefile.PE('FlareCalc.exe')
print('ImageBase', hex(p.OPTIONAL_HEADER.ImageBase))
for s in p.sections:
    print(s.Name.rstrip(b'\x00').decode(), hex(s.VirtualAddress), hex(s.PointerToRawData), hex(s.SizeOfRawData))
"
ImageBase 0x140000000
.text 0x1000 0x400 0xd3200
.rdata 0xd5000 0xd3600 0xc400
.data 0xe2000 0xdfa00 0x5e00
.pdata 0xea000 0xe5800 0x9000
.fptable 0xf3000 0xee800 0x200
.rsrc 0xf4000 0xeea00 0x200
```

Bằng chứng quyết định: bảng import chỉ có `CreateFileW` (mở `CONOUT$` để debug output),
**không** có `ReadFile`, `MapViewOfFile`, `CreateFileMappingW`, `VirtualAlloc`.
⇒ Không tồn tại loader nào đọc overlay. Cái máy tính "thật" này chỉ là màn che; "engine"
đang chờ được kích hoạt nằm gọn trong bảng ASN.1 của chứng thư.

## Bản đồ giải quyết

```
FlareCalc.exe
  │
  ├─ .text/.rdata/.data → GUI máy tính + hàng trăm decoy CRT/UCRT
  │     ⚠ import KHÔNG có ReadFile / MapViewOfFile / CreateFileMappingW / VirtualAlloc
  │       ⇒ overlay là payload tĩnh cho người giải, không phải input của chương trình
  │
  └─ overlay 0xEEC00 (WIN_CERTIFICATE, type 2 = PKCS#7)
        └─ certificates[0] → 3 cert X.509 giả (CN=Never Gonna Let You Down, FLARE-ON CTF)
              └─ extension OID 1.3.6.1.4.1.13839.1
                    └─ OCTET STRING @ file 0xEF471 (526.579 byte)
                          └─ SEQUENCE { SEQUENCE {INTEGER id, OCTET STRING blob} × 1035 }
                                │
                                ├─ 1.033 blob → stub x86-64 128–188 B (node của DFA)
                                ├─ 1 blob     → dữ liệu (id 9990: 118 B blob → 40 B ciphertext)
                                └─ 1 blob     → code x86-64 THẬT 46.500 B (id 3821 — mồi, không mã hoá)
                                      │
      GIẢI MÃ ────────────────────────┘
        │  seed = fold₃₁(md5(pwd ‖ u32le(id)))
        │  keystream LCG chạy **mỗi byte ct (kể cả byte rác)**: s = s·1103515245+12345,
        │  ks[p] = s & 0xFF;  blob_thật[R[j]] = ct[R[j]] ^ ks[R[j]]
        │  (R = lịch vị trí GLOBAL gap 2..4, dùng chung mọi entry — byte rác = keystream
        │   nhìn xuyên qua phần đệm 0)
        ▼
      1.033 stub + 9990      (capstone: 155.522/155.561 byte = 99,97%)
        │
      WALK ── mỗi stub: emu 95 ký tự printable → eax∈{entry-id} là nhánh hợp lệ
        │    DFS + ràng buộc "tới node 4485 đúng sau 32 bước" ⇒ nghiệm DUY NHẤT
        │    state 32 byte tích luỹ qua 3 ghi/j (j, j+7, j+19 mod 32) = 96 ghi = đủ 32 byte ×3
        ▼
      state = 32-byte key
        │
      NODE 4485 ── XTEA-biến-thể: k[i] = key32[16+4i]^key32[4i];
        │    delta = 0x8c032fc1 ⊕ 0x12345678 = 0x9E3779B9; sum₀ = delta≪5 = 0xC6EF3720
        │    5 block BE × 32 vòng → 40 byte plaintext
        ▼
      flag (40 byte ASCII)
```

## 1. Overlay = Authenticode giả

```bash
$ python3 -c "
import struct
raw = open('FlareCalc.exe','rb').read()
print(struct.unpack('<IHH', raw[0xEEC00:0xEEC00+8]))
"
(529568, 512, 2)     # dwLength, wRevision=0x200, wCertificateType=2 = PKCS_SIGNED_DATA
```

Bên trong: `signedData` → `certificates[0]` chứa **3 chứng thư tự ký**; cert #3 (527.419 byte,
`CN=Never Gonna Let You Down, O=FLARE-ON CTF`) mang một **extension tự chế**:

```
OID 1.3.6.1.4.1.13839.1  →  06 08 2b 06 01 04 01 8a 39 01
```

Extension này chứa OCTET STRING @ file `0xEF471`, dài 526.579 byte — chính là bảng dữ liệu.

```bash
$ python3 scripts/flarecalc_table.py
records: 1035
id range 49..65469
```

Mỗi record: `SEQUENCE { INTEGER <id>, OCTET STRING <blob> }`. Blob của các stub đo ≈3,01 lần
plaintext (`52090`: 456 → 152; `9990`: 118 → 40; `4485`: 1155 → 384) và trộn **2 loại byte**:
~1/3 byte thật + ~2/3 byte nhiễu. 3 bit thấp của byte nhiễu **đóng băng theo hằng per-entry**
(chỉ nhận {0,1,2,4,5,6}, không bao giờ 3 hay 7).

```
min/median/max blob: 118 434 46500
biggest: [(3821, 46500), (3829, 2888), (3827, 1734), (3824, 1311), (4485, 1155)]
```

## 2. Mô hình giải mã — "mask 0x80" chỉ là artifact

Key schedule (đo trực tiếp từ binary, chỉ dùng phần này là đủ giải mã):

- **seed riêng từng entry**: `seed = fold₃₁(md5(pwd ‖ u32le(id)))` — fold từng byte md5:
  `l = (l·31 + b) & 0xffffffff`;
- keystream LCG: `s = (s·1103515245 + 12345) & 0xffffffff`, khởi động từ `seed`.

Điểm mấu chốt (sau nhiều lần đoán sai):

1. **LCG tiến thêm MỖI byte position của blob** — kể cả byte rác/đệm — không reset, không
   cycle qua lại. Byte giải mã: `plain[p] = ct[p] ^ (s_p & 0xFF)`.
2. Byte rác chính là **keystream nhìn xuyên qua phần đệm 0** của plaintext:
   `ct[p] ^ ks[p] = 0`. Đây là lý do mọi phép "khôi phục lịch vị trí" hoạt động: các
   header/đệm 0 lộ kênh keystream.
3. Lịch vị trí thật `R` **dùng chung cho mọi entry** (gap 2..4: 0, 2, 5, 7, 10, 14, 18, 22,
   24, 28, 30, 33, …) — một đợt DP/consensus trên 1.033 entry khôi phục được nó và nó tái sử
   dụng được cho mọi entry.

Vì sao biết là đúng mô hình: dùng **known-plaintext của node 52090** (stub đầu tiên của
đường đi — disasm sạch 152 byte). Chạy 5 biến thể keystream đối chiếu:

```bash
$ python3 scripts/verify_ks2.py
cycled low8  (old)   mismatches  63/152   first-bad@44: got a4 want 24
cont per-pos low8    mismatches   0/152
cont per-pos hi16    mismatches 152/152   first-bad@0: got 28 want 4c
cont per-real low8   mismatches 150/152   first-bad@1: got e8 want 8b
cont per-real hi16   mismatches 150/152   first-bad@0: got 28 want 4c
```

- `cycled low8 (old)` — mô hình cũ nghĩ keystream cycle theo `p%128` và phải "mask 0x80"
  bắt lỗi ở byte thứ 128+ — mismatch 63/152. Tất cả sai lệch đều rơi ở *position ≥ 128*:
  byte `a4` vs `24`, `90` vs `10`, `80` vs `00` — chênh nhau bit 7 ⇒ **cái mask 0x80 chỉ là
  artifact của phép lấy số dư 128**, không phải feature thật của mã hoá.
- **`cont per-pos low8` = 0/152** — khớp tuyệt đối. Đây là mô hình đúng.
- `(s>>16)&0xFF` (công thức mà hint blog paraphrase lại) → 152/152 sai ⇒ bài blog gốc luôn
  khớp hằng số 1103515245/12345 + byte thấp, chỉ phần diễn giải là bịa.

Giải toàn bộ bảng:

```bash
$ python3 scripts/decrypt_cont.py
...
capstone coverage 155522/155561 (99.97%), incomplete: 2
```

1.033 stub giải ra, **disasm chuẩn 99,97%**. 2 entry không đầy đủ: `3829` kết thúc giữa một
lệnh (capstone bao phủ 960/961 byte) và `9990` là dữ liệu 40 byte chứ không phải code.
Kích thước stub sau giải tập trung ở 128–188 byte (1025/1033, median 144) — đúng khái niệm
"template nhỏ".

**Mồi nhử:** record `3821` là 46.500 byte code **không mã hoá** — capstone cover 100% (9.574
lệnh) khi đọc nguyên blob, và các `call` trỏ vào chính `.text` của file:

```asm
; id 3821, đặt tại ImageBase+0x1000
0x140001000  mov  qword ptr [rsp+0x10], rdx
0x140001005  mov  qword ptr [rsp+8], rcx
0x14000100a  sub  rsp, 0x568
0x14000102d  call 0x140003a84
```

Phần đầu nhìn rất giống một stub thật; nó nằm thoải mái trong bảng, không cần giải mã —
bẫy để người giải lãng phí thời gian phân tích một hàm 9 KB không bao giờ chạy.

## 3. Giải phẫu stub: head / stall-loop / tail

Mỗi stub tuân theo 1 template 3 phần (95,6% stub cùng kiểu; số còn lại là biến thể).

**(a) Prologue + head**: `mov r9, rdx` (state ptr), `mov r8d, 0xF4240` (giới hạn loop),
`movzx edx, cl` (ký tự), rồi **3 ghi/entry-index**:

```
state[(j+0)%32]  = g1(state[j], state[j±k], cl)     ; add/xor tổ hợp
state[(j+7)%32] ^= f2(...)
state[(j+19)%32] += g3(...)
```

Với stub thứ k (j = (k−1) mod 32). Trên đường 32 bước: **mỗi byte state nhận đúng 3 lần
ghi** (từ j, j+7, j+19) — tổng 96 ghi phủ đủ 32 byte ×3. Head thật của node 5295:

```asm
mov r9, rdx                  ; r9 = state
movzx edx, cl                ; edx = cl
mov al, [r9+6]
add al, [r9+5]
xor al, dl
add al, 0x36
mov [r9+5], al               ; state[5]  = (s[6]+s[5])^cl + 0x36
sub al, 0x6f
xor [r9+0xc], al             ; state[12] ^= state[5]-0x6f
mov al, [r9+0xc]
xor al, 0xe6
add [r9+0x18], al            ; state[24] += state[12]^0xe6
```

**(b) stall-loop — "triệu vòng học trang API"**:

```asm
mov dword [rsp+0x10], 0          ; acc
mov dword [rsp+8],    0          ; cnt
.loop:
  eax = cnt; ecx = cnt; eax = acc; ecx += eax; acc = ecx
  eax = cnt; inc eax; cnt = eax
  eax = cnt; cmp eax, r8d (0xF4240); jb .loop
```

Σ₀..999999 = 999.999·1.000.000/2 = 499.999.500.000 ≡ **0x6A4AE6E0** (mod 2³²). Ngay sau loop:
`sub eax, 0x6A4AE6E0` — **toán học bị khử thành 0**; mục đích của 1 triệu vòng này là tiêu thời
CPU trên người phân tích (mà thật ra cũng là một dạng decoy nữa). Vá khi mô phỏng: thay
`mov r8d, 0xF4240` → `mov r8d, 0`, thay init acc → `0x6A4AE6E0` để loop chạy đúng 1 lần mà
hằng số học giữ nguyên (`node_emu.py: patch_code`).

**(c) Tail — công thức junk tạo node kế tiếp**: đọc 1 byte state (lựa chọn per-node), tính
imul/rol/xor tham số với cl và acc, kết quả = **eax = id node kế**. Ba công thức đối chiếu
bằng tay + xác minh (thay `acc` patched = 0x6A4AE6E0):

| Node | Công thức tail (số học giữ nguyên của binary) | Với cl… | eax = node kế |
|---|---|---|---|
| 52090 | `rol(s7·0x1337 − 0x55555556, 11) ⊕ rol(cl·0x1337 + 0x55555555, 5) ⊕ (acc−0x6A4AE6E0) ⊕ 0x6B82E2BF` | 'F' | 54272 ✓ |
| 54272 | `((cl²·0x33 + s25·0x1337) ⊕ 0x68925143) + 0x976A7CFA ⊕ (acc−0x6A4AE6E0)` | 'L' | 44269 (0xACED ✓) |
| 5295  | `(rol(s24·0x1337, 7) + cl³·0x11) ⊕ (acc + 0x95B51920) ⊕ 0x098188A3` | 'O' | 9340 ✓ |

Tail của 52090, disasm thật:

```asm
movzx eax, byte [r8+7]       ; state[7]
imul   ecx, eax, 0x1337
mov    eax, [rsp+0x10]       ; acc
imul   edx, edx, 0x1337      ; edx = cl
sub    eax, 0x6a4ae6e0       ; (acc − Σ) = 0 trong run thật
sub    ecx, 0x55555556
rol    ecx, 0xb
add    edx, 0x55555555
rol    edx, 5
xor    edx, ecx
xor    eax, edx              ; eax = (acc−Σ) ⊕ junk
xor    eax, 0x6b82e2bf
ret
```

Chú ý chút Easter egg: node 54272 trả về **0xACED** = 44269 với cl='L'. Một số stub thêm
**cpuid + SSE float junk** (node 3394: `mulss/cvttss2si` tạo `rbx`, rồi `xor eax, ebx`;
`sar edx, 0x1a; and edx, 1` — tất cả chỉ là thuật ngữ làm rối).

## 4. Walk 32 bước: đi mê cung lấy khóa

Ở mỗi node, emu stub với **95 ký tự printable** đưa vào `cl` (state cũng được đưa vào
`rdx`/`r8`); nhánh hợp lệ = `eax` rơi vào vùng entry-id.

- **Hầu hết node chỉ có 1 ký tự** dẫn vào node-id space (branching factor = 1);
- Một số ít node trở về **2–3 id** (3394: 'E'→5295 và 'G'→5293; 14703: 'h'→27264, `'`→27343,
  `-`→27333) — **nhánh chết** bị lọc tự nhiên: nhánh đi lạc sẽ dead-end trong 1–2 bước;
- ⇒ DFS dưới ràng buộc **"tới node 4485 đúng sau bước 32"** + để nhánh chết tự cạn ⇒ nghiệm
  DUY NHẤT; tổng budget ~4.085 lần mô phỏng stub (~43 node × 95 ký tự).

Lưu ý khi mô phỏng: mỗi lần `emu.run` phải **zero toàn bộ GP regs + EFLAGS** trước (không thì
kết quả lệch theo carry-over) và phải có return address sentinel trên stack (`node_emu.py` đã vá
cả hai).

Trace đầy đủ 32 bước (derivation tự động):

| Step | Node | Ký tự | Node kế | Step | Node | Ký tự | Node kế |
|---:|---|---|---|---:|---|---|---|
| 1 | 52090 | `F` | 54272 | 17 | 11353 | `y` | 38907 |
| 2 | 54272 | `L` | 44269 | 18 | 38907 | `r` | 61188 |
| 3 | 44269 | `A` | 60903 | 19 | 61188 | `i` | 897 |
| 4 | 60903 | `R` | 3394 | 20 | 897 | `n` | 36897 |
| 5 | 3394 | `E` | 5295 | 21 | 36897 | `t` | 14703 |
| 6 | 5295 | `O` | 9340 | 22 | 14703 | `h` | 27264 |
| 7 | 9340 | `N` | 4541 | 23 | 27264 | `_` | 60861 |
| 8 | 4541 | `_` | 3992 | 24 | 60861 | `K` | 43128 |
| 9 | 3992 | `A` | 56850 | 25 | 43128 | `e` | 45481 |
| 10 | 56850 | `S` | 43446 | 26 | 45481 | `y` | 49853 |
| 11 | 43446 | `N` | 30165 | 27 | 49853 | `_` | 18431 |
| 12 | 30165 | `1` | 29720 | 28 | 18431 | `2` | 54671 |
| 13 | 29720 | `_` | 7272 | 29 | 54671 | `0` | 64067 |
| 14 | 7272 | `L` | 6697 | 30 | 64067 | `2` | 15358 |
| 15 | 6697 | `a` | 8047 | 31 | 15358 | `6` | 60131 |
| 16 | 8047 | `b` | 11353 | 32 | 60131 | `!` | **4485** |

Chuỗi ký tự cộng lại là `FLAREON_ASN1_Labyrinth_Key_2026!`, và state 32 byte cuối chính là
**khóa XTEA** mà node 4485 cần:

```
670daa0ff05e7d85472eeb55a716a7b88d63019c27ee22ea447fd4fde87c013d
```

## 5. Node 4485: XTEA-biến-thể

Record 9990 sau giải là **40 byte** — chính là ciphertext XTEA:

```
64c3d61fe488f41be21acf1c6ab275959da7725ef1edcc1a1deec9068b827b7dc348f0ff49c07783
```

Node 4485 (384 byte) là **decryptor** với quy ước gọi:

```
rcx = output buffer      rdx = ciphertext (40 B)      r8 = key (32 B)
```

Cấu trúc đo được từ disasm (không phỏng đoán):

1. **Key schedule tự làm**: 4 dword `k[i] = *(u32)(key+0x10+4i) ⊕ *(u32)(key+4i)`
   (8 dword key nén thành 4), lưu ở `rsp[0..16)`;
2. **delta thật được che giấu bằng XOR chéo**: `[rsp+0x58] = 0x12345678`,
   `[rsp+0x50] = 0x8c032fc1`, và

   ```
   0x8c032fc1 ⊕ 0x12345678 = 0x9E3779B9      ← delta XTEA chuẩn!
   ```
3. sum khởi đầu `= delta≪5 = 0xC6EF3720 = 32·delta` (32 vòng) rồi **giảm dần theo vòng**
   (chiều decrypt của XTEA);
4. **5 block × 8 byte** (đầu vào đọc theo big-endian, bswap ra); mỗi block 32 vòng:

   ```
   v1 -= ((v0>>5)^(v0<<4)) ⊕ (k[(sum>>11)&3] + sum); sum -= delta
   v0 -= ((v1>>5)^(v1<<4)) ⊕ (k[sum&3] + sum)
   ```
5. **strlen**: cuối cùng đếm số byte non-NUL cận 40 → trả về `eax`.

## 6. Lời giải

```bash
$ python3 scripts/solve_flarecalc.py

=== decrypt_cont.py ===
capstone coverage 155522/155561 (99.97%), incomplete: 2
=== walk_final.py ===
budget used 4085, solutions 1
=== xtea_final.py ===
walk   : 'FLAREON_ASN1_Labyrinth_Key_2026!'
key    : 670daa0ff05e7d85472eeb55a716a7b88d63019c27ee22ea447fd4fde87c013d
ct(9990): 64c3d61fe488f41be21acf1c6ab275959da7725ef1edcc1a1deec9068b827b7dc348f0ff49c07783
eax (strlen) = 40
out          : b'<40 byte ASCII>\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

FLAG: '<40 byte ASCII>'

*** ALL STAGES PASSED ***
```

Ba phép cross-check độc lập cùng khớp: disasm của stub đầu đường (99,97% capstone), khóa 32
byte do walk tạo ra, và plaintext 40 byte kết thúc bằng `@flare-on.com`.

## 7. Bài học

1. **Known-plaintext là thước đo phân biệt mô hình.** Chỉ khi có known-plain của node 52090
   mới tách được `cycled` vs `continuous`, `low8` vs `hi16` — con số **0/152** là điểm phán
   xét (falsifiable). Bảng 63/152 mismatch (toàn ở vị trí ≥ 128) chính là "cơ hội vàng" tiết
   lộ dạng thật của keystream.
2. **Đọc binary trước, công thức sau.** Một dòng kiểm tra modulo (`1103515245 ≡ 12345 ≡ 0
   mod 3`) đủ bác bỏ công thức "skip = roll%3" của hint. Vá stall-loop bằng đúng hằng
   `0x6A4AE6E0` giữ nguyên số học mà không cần chạy 1 triệu vòng.
3. **Chân stub là template; biến thể chỉ là paraphrase.** Trong 1.033 stub, template chính
   chiếm phần rất lớn (1025/1033 nằm dải 128–188 byte); tìm ra 1 template → emu cả nghìn
   node theo cùng cơ chế. Key schedule cũng vậy: 1 thiết kế, dùng cho toàn bảng.
4. **Flag tự làm oracle.** Plaintext phải kết thúc `@flare-on.com`, `strlen = 40`, và key từ
   walk phải khớp với nguồn độc lập — ba phép test cross-check cả bảng key schedule + walk emu
   + XTEA.

## Flag

```
t3mplat3s_asn_and_j1t_0h_my@flare-on.com
```

*"…templates, ASN and JIT — oh my!"* — nói về stub template, substrate ASN.1, và thân phận
"JIT engine" giả. Lấy cảm hứng câu *"lions and tigers and bears — oh my!"* của The Wizard of Oz.
