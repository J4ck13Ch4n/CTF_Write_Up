# FLARE-On 13 — Challenge 3: FlareOn13.doc

**Flag:** `Ju$7_4_l177l3_7r34$ur3_HUN7@flare-on.com`

> *"As part of our testing protocols, we need to assess your level of stress when examining a simple document file."*

## Tổng quan

Archive `3-flareon13_doc.7z` (mật khẩu `flare`) chứa một file duy nhất là `flareon13.doc` (1,855,887 byte). Tuy mang đuôi `.doc`, đây **không phải** OLE2/Word: `olefile` báo `not an OLE2 structured storage file`. Byte đầu tiên là mã x86 16-bit gồm toàn ký tự in được, kiểu EICAR.

Thực chất đây là một **polyglot**: một file hợp lệ cùng lúc với nhiều định dạng. Mỗi lớp giấu một "mảnh" chuỗi. Sáu mảnh này là đầu vào cho bộ kiểm tra viết bằng Crystal nằm sâu bên trong, và bộ kiểm tra sẽ giải ra flag.

```
offset        định dạng                         mảnh
──────────────────────────────────────────────────────────────────────────
0x000000      DOS .COM (biến thể EICAR)          FLARE-STANDARD-ANTIVIRUS-TEST-FILE!
0x000084      %PDF-1.7 (RC4-40)
  obj 1       └─ stream 1.8 MB  ── Raw CD image (2352 B/sector, Mode 1)
                   └─ UDF 1.02  ── IUVD.LVInfo1   udf_tagged_descriptor
                        ├─ README.TXT  "benign corpus payload"
                        └─ click_me    Mach-O fat (2 × arm64)
                             ├─ slice 0 (C, fire demo)       Ød1n_373rn4l_fl4r3
                             └─ slice 1 (Crystal) ── CHECKER → FLAG
  obj 5       └─ content stream: text EBCDIC     mainframe_ebcdic_ghost
  obj 8       └─ ảnh JBIG2 808×48                jbig2_fax_geometry
0x1C4E3F      ZIP: flag.txt (ZipCrypto + Reduce) reduce_not_deflate
0x1C4F8F      VHD footer "conectix" (fixed disk, UniqueID = FLAREONPOLYGLOT!)
```

Định dạng nào cũng chịu được "rác" ở đầu hoặc cuối file theo cách riêng của nó, nên có thể chồng chúng lên nhau:

* **COM** chạy từ byte 0.
* **PDF**: trình đọc tìm `%PDF` trong khoảng 1024 byte đầu và dùng `xref`/`startxref` ở cuối.
* **ZIP** đọc từ End of Central Directory ở cuối file.
* **VHD** cố định chỉ cần 512 byte footer ở cuối.
* **CD thô** dùng sector 2352 byte tính từ offset 0 và nằm lọt trong stream của PDF object 1.

## 1. Lớp DOS COM: biến thể EICAR

```
h  X5`!P[h @X5#`0G h @X5%`0G!h @X5"`0G"h @X53`0G#h @X57`0G$h  X5@!PZh  X5|!P[h  X5[)P^)7CC)7H+H*EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$
```

Disassemble ở chế độ 16-bit, base `0x100`:

```asm
push 0x2020 / pop ax / xor ax,0x2160 / push ax / pop bx     ; bx = 0x0140
push 0x4020 / pop ax / xor ax,0x6023 / xor [bx+0x20],al      ; 0x160 ^= 0x03  'E'→'F'
push 0x4020 / pop ax / xor ax,0x6025 / xor [bx+0x21],al      ; 0x161 ^= 0x05  'I'→'L'
push 0x4020 / pop ax / xor ax,0x6022 / xor [bx+0x22],al      ; 0x162 ^= 0x02  'C'→'A'
push 0x4020 / pop ax / xor ax,0x6033 / xor [bx+0x23],al      ; 0x163 ^= 0x13  'A'→'R'
push 0x4020 / pop ax / xor ax,0x6037 / xor [bx+0x24],al      ; 0x164 ^= 0x17  'R'→'E'
push 0x2020 / pop ax / xor ax,0x2140 / push ax / pop dx     ; dx = 0x0160 (chuỗi)
push 0x2020 / pop ax / xor ax,0x217c / push ax / pop bx     ; bx = 0x015c
push 0x2020 / pop ax / xor ax,0x295b / push ax / pop si     ; si = 0x097b
sub [bx],si / inc bx / inc bx / sub [bx],si                 ; "H+H*" → CD 21 CD 20
                                                            ; = int 21h ; int 20h
```

Code tự sửa `EICAR` thành `FLARE` và biến `H+H*` thành `int 21h (AH=9) ; int 20h`. Emulate bằng Unicorn (`UC_MODE_16`, hook `UC_HOOK_INTR`) thì chương trình in ra:

```
FLARE-STANDARD-ANTIVIRUS-TEST-FILE!
```

**Mảnh #1:** `FLARE-STANDARD-ANTIVIRUS-TEST-FILE!`

## 2. Lớp PDF

```
1 0 obj << /Length 1839086 >> stream …            ← chứa CD image (mục 4)
4 0 obj << /Type /Page /MediaBox [0 0 14400 14400] /UserUnit 75000
           /Contents 5 0 R /Resources << /Font << /F1 6 0 R >> /XObject << /Im 8 0 R >> >> >>
8 0 obj << /Subtype /Image /Width 808 /Height 48 /BitsPerComponent 1
           /Filter /JBIG2Decode /Length 381 >>
9 0 obj << /Filter /Standard /V 1 /R 2 /O <2055c7…> /U <7a39b1…> /P -44 >>
trailer << /Root 2 0 R /Encrypt 9 0 R /ID [<466c6172654f6e506f6c79676c6f7431> …] >>   ← "FlareOnPolyglot1"
```

PDF được mã hóa bằng **Standard Security Handler V1/R2 (RC4 40-bit)**. Tính key theo Algorithm 3.2 với **user password rỗng** thì `RC4(key, PAD) == /U`, tức mở được ngay:

```python
key = md5(PAD + O + pack('<i', P) + ID).digest()[:5]
objkey(n) = md5(key + n.to_bytes(3,'little') + b'\0\0').digest()[:10]
```

Trang có kích thước 14400 × 14400 với `UserUnit 75000`, tương đương khoảng 1.08 tỷ đơn vị mỗi cạnh. Khi mở bằng trình xem thông thường, mọi thứ thành một chấm nhỏ khó thấy.

### 2.1 Content stream (obj 5): text EBCDIC vô hình

Sau khi giải mã, stream gồm các path vẽ logo "FLARE-ON" và hai lệnh đáng chú ý:

```
BT /F1 1 Tf 3 Tr 50 50 Td <9481899586998194856d8582838489836d878896a2a3> Tj ET
q 12 0 0 1 -80 -80 cm /Im Do Q
```

* `3 Tr` là text rendering mode 3 (*invisible*): chữ có trong file nhưng không được vẽ.
* Chuỗi hex không phải ASCII mà là **EBCDIC** (codepage 500, của mainframe IBM):

```python
>>> bytes.fromhex('9481899586998194856d8582838489836d878896a2a3').decode('cp500')
'mainframe_ebcdic_ghost'
```

**Mảnh #2:** `mainframe_ebcdic_ghost`

### 2.2 Ảnh JBIG2 (obj 8)

Ảnh 1-bit 808×48 nén bằng **JBIG2**, codec gốc từ máy fax. Nó được đặt tại `(-80, -80)`, nằm ngoài vùng nhìn thấy của trang. PyMuPDF (MuPDF có decoder JBIG2) giải mã được:

![JBIG2](im8.png)

**Mảnh #3:** `jbig2_fax_geometry`

Phần vector của trang chỉ là logo FLARE-ON, không có thông tin gì thêm:

![logo](drawing.png)

## 3. Lớp ZIP: `flag.txt`

Ở offset `0x1C4E3F` có một ZIP nhỏ, gồm local header, central directory và EOCD:

| Trường | Giá trị |
|---|---|
| Tên | `flag.txt` |
| General purpose flag | `0x0001`: mã hóa **ZipCrypto** |
| Compression method | **`2` = Reduced (factor 1)** |
| CRC-32 | `0x25130DEA` |
| Size | 222 → 18 byte |

Python `zipfile` báo `That compression method is not supported`. **Reduce** là thuật toán của PKZIP 0.9x (1989), đã bị Deflate thay thế từ lâu.

**Mật khẩu:** thử các ứng viên với byte kiểm tra ZipCrypto (byte thứ 12 của header giải mã phải bằng `CRC >> 24 = 0x25`). Chỉ có `infected` qua, đây là mật khẩu quen thuộc để chia sẻ mẫu malware. Riêng phép kiểm này có 1/256 khả năng khớp nhầm, nhưng CRC-32 sau khi giải nén xác nhận lại.

**Unreduce** (theo APPNOTE / `unreduce.c` của Info-ZIP):

1. Đọc 256 *follower set*, theo thứ tự `j = 255 … 0`: `N = bits(6)`, rồi `N` byte `bits(8)`.
2. Giải mã từng byte: nếu `S[last]` rỗng thì `c = bits(8)`. Nếu không, đọc `bits(1)`: bằng 1 thì `c = bits(8)`, bằng 0 thì `c = S[last][bits(B(N))]`.
3. Máy trạng thái cho factor 1 (`L = 0x7F`, `DLE = 0x90`): khi gặp `DLE, V[, len2], off` thì chép `len + 3` byte từ vị trí `((V >> 7) << 8) + off + 1` byte trước đó.

```
>>> unreduce(zipcrypto_decrypt(b'infected', data)[12:], factor=1, size=18)
b'reduce_not_deflate'          # CRC32 = 0x25130dea ✓
```

**Mảnh #4:** `reduce_not_deflate`

## 4. Lớp CD thô → UDF

### 4.1 Nhận diện sector CD

Quét các khối khác 0 thì thấy một mẫu lặp lại đúng mỗi 2352 byte:

```
00 FF FF FF FF FF FF FF FF FF FF 00 | 00 02 01 | 01
└──────────── sync 12 byte ───────┘   M  S  F   mode
```

Đây là **sector CD-ROM thô Mode 1** (2352 byte, gồm sync 12 byte, header 4 byte, user data 2048 byte và EDC/ECC 288 byte). Header chứa địa chỉ MSF dạng BCD với `LBA = (M·60 + S)·75 + F − 150`, và kiểm tra thấy `offset = 2352 × LBA`. Sector 0 bắt đầu từ byte 0 của file, nên 16 byte đầu của nó bị header COM/EICAR đè lên. Toàn bộ CD nằm gọn trong stream 1.8 MB của PDF object 1.

```python
iso = b''.join(D[l*2352+16 : l*2352+16+2048] for l in range(len(D)//2352))   # 789 sector
```

### 4.2 UDF

Ảnh ISO thu được không có `CD001`, nhưng có các Volume Structure Descriptor `BEA01` / `NSR02` / `TEA01` ở sector 16–18, tức là filesystem **UDF**. `pycdlib` bắt buộc phải có PVD ISO9660 nên từ chối, vì vậy mình tự viết parser tối thiểu:

```
AVDP (sector 256) → Main VDS (sector 20..25)
  20  tag 1  Primary Volume Descriptor
  21  tag 4  Implementation Use Volume Descriptor   ← !!!
  22  tag 5  Partition Descriptor   start = 272, length = 253
  23  tag 6  Logical Volume Descriptor  LVID "FLAREON", FSD @ lb 0
  24  tag 7  Unallocated Space Descriptor
  25  tag 8  Terminating Descriptor
FSD (lb 0) → root File Entry (lb 2) → File Identifier Descriptors:
  /click_me     lb 4   502816 byte
  /README.TXT   lb 5   22 byte   "benign corpus payload"
```

**Implementation Use Volume Descriptor** (sector 21) chứa phần *LV Information* dạng dstring:

| Trường | Giá trị |
|---|---|
| LVI Identifier | `FLAREON` |
| **LVInfo1** | **`udf_tagged_descriptor`** |
| LVInfo2 | `DiscRecording Framework` |
| LVInfo3 | `9.0.3d5` |

LVInfo2/3 cho thấy đĩa được tạo bằng DiscRecording.framework của macOS. LVInfo1 thì đã bị thay bằng mảnh chuỗi.

> Lúc đầu mình bỏ sót trường này. Mình chỉ tìm ra nó sau khi có danh sách MD5 ở mục 6: brute-force MD5 của mọi chuỗi in được trong file, và hash thứ sáu khớp với `udf_tagged_descriptor`.

**Mảnh #5:** `udf_tagged_descriptor`

## 5. `click_me`: Mach-O fat, slice 0 (arm64)

```
cafebabe  nfat_arch = 2
  [0] cputype 0x0100000C (ARM64) subtype 0  offset 0x04000 size 0x10BD0   ← C nhỏ
  [1] cputype 0x0100000C (ARM64) subtype 3  offset 0x18000 size 0x62C20   ← Crystal
```

Slice 0 rất nhỏ (`__text` chỉ 0xB0C byte). Nó import `ptrace`, `usleep`, `write`, `bzero`, `memcpy`, `memmove`, và chứa chuỗi *"Strings ? Where we're going, we don't need strings..."*. Chương trình vẽ một **hiệu ứng lửa ASCII** trên terminal:

* `ptrace(31 /* PT_DENY_ATTACH */, 0, 0, 0)` để chống debugger.
* Palette được XOR với `0x80` trong `__const`, giải ra `\e[38;5;52m`, `…124m`, `…196m`, `…208m`, `…220m`, `…231m` và dải ký tự ` .,:;=+*oahHGM#B&@`.
* 2400 hạt, RNG xorshift32 (`<<13, >>17, <<5`), vòng lặp `write` + `usleep(33000)`.

Chuỗi được in ra ở mỗi frame (19 byte, `memcpy` vào dòng trạng thái) được tính **một lần** ở đầu `main`:

```text
W[0..15]  = hằng từ __const (0x1250..0x127F, có "atot_yllekafalf_")
W[16..79] = W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]      ; csel theo byte [x22] luôn = 0
                                                     ;   → KHÔNG rotl 1  ⇒ SHA-0
80 vòng kiểu SHA-1 (f/K chọn theo (t*205)>>12 = t/20)
out[0..15]  = hex(h0) ‖ hex(h1)            XOR  f0 fd 54 06 5f 3c 05 03 01 41 5a 52 5d 3d 5f 08
out[16..18] = hex(h2)[0..2]                XOR  50 4a 07
```

Emulate đoạn `0x1000006B4 … 0x100000AA4` bằng Unicorn ARM64 (hook bỏ qua `bl ptrace`):

```
hex digest = "3e071c64234f1b9d…"
out        = c3 98 64 31 6e 5f 33 37 33 72 6e 34 6c 5f 66 6c 34 72 33
           = "Ød1n_373rn4l_fl4r3"       (c3 98 = U+00D8 'Ø' trong UTF-8)
```

Hai byte đầu *không thể* là ASCII: một chữ số hex XOR `0xF0`/`0xFD` luôn ra byte ≥ 0x80. Chúng được chọn để tạo thành đúng một ký tự UTF-8 hợp lệ là `Ø` ("Odin eternal flare").

**Mảnh #6:** `Ød1n_373rn4l_fl4r3`

Trong file còn có chuỗi `totally_fake_flag`, nhưng đó là mồi nhử.

## 6. `click_me` slice 1: bộ kiểm tra viết bằng Crystal

Slice thứ hai là một binary **Crystal**. Toàn bộ chuỗi lỗi của stdlib đã bị đổi sang leet-speak (`N3g471v3 c4p4c17y`, `1nd3x 0u7 0f b0und$`…), nên không grep được. Chuỗi của chương trình chính nằm ở `0x10004E820`:

```
"flag["   "]> "   "n0p3 ("
```

### 6.1 Luồng xử lý (`__crystal_main`, khoảng `0x100001B60`)

```crystal
inputs = [] of String
6.times do |i|
  print "flag[#{i + 1}]> "
  inputs << gets.chomp            # bỏ \r\n
end

expected = EXPECTED_MD5.dup       # tập 6 digest
inputs.each do |s|
  d = md5(s)
  expected.delete(d)              # so 16 byte, thứ tự nhập không quan trọng
end
unless inputs.size == 6 && expected.empty?
  puts "n0p3 (...)"
  exit
end

key = Bytes.new(32)
inputs.each { |s| key ^= sha256(s) }      # 0x1000027AC..0x100002A6C
puts rc4(key, CIPHERTEXT)                  # 0x100003514..0x1000035F0, RC4 chuẩn
```

Bảng K của MD5 và SHA-256 được sinh lúc chạy (SHA-256 tìm số nguyên tố rồi lấy `isqrt`/`icbrt` 128-bit), nên không tìm thấy hằng số chuẩn trong file.

### 6.2 Dữ liệu giấu dạng nibble

Trong `__literals` ở `0x35E30` có 272 byte đều dạng `0x8?`. Mỗi byte là một chữ số hex `0x80 | nibble`:

```python
hx = ''.join('%x' % (b & 0xf) for b in slice1[0x35e30:0x35f40])   # 272 ký tự hex
```

| # | 32 hex (MD5) | Khớp với |
|---|---|---|
| 0 | `d82180ab7986e8c8286ef00f16c04885` | `FLARE-STANDARD-ANTIVIRUS-TEST-FILE!` |
| 1 | `555cca3a364f57bd4e550e8758f1c08d` | `mainframe_ebcdic_ghost` |
| 2 | `c790cb74ddc76a4f9f83c9f79882d6fc` | `jbig2_fax_geometry` |
| 3 | `cf0cbd1b55755a81ff87f2be8fba8ebf` | `udf_tagged_descriptor` |
| 4 | `d400db493c31ebf21fa0b2a4adeae070` | `reduce_not_deflate` |
| 5 | `9fc1de183e2761585dfce907afa249dc` | `Ød1n_373rn4l_fl4r3` |
| — | 80 hex còn lại | ciphertext 40 byte |

## 7. Lời giải

Script đầy đủ: [solve.py](solve.py). Script tự trích 4 mảnh từ file gốc (COM, EBCDIC, ZIP, UDF). Hai mảnh còn lại (ảnh JBIG2 và output của Mach-O) được điền sẵn từ kết quả render/emulate ở trên. Sau đó script kiểm tra cả 6 MD5 với blob trong slice Crystal rồi giải flag. Phần lõi:

```python
key = bytearray(32)
for f in frags:
    for i, b in enumerate(hashlib.sha256(f.encode()).digest()):
        key[i] ^= b
print(rc4(bytes(key), bytes.fromhex(hx[192:])).decode())
```

```
$ python solve.py
fragment: FLARE-STANDARD-ANTIVIRUS-TEST-FILE!
fragment: mainframe_ebcdic_ghost
fragment: jbig2_fax_geometry
fragment: udf_tagged_descriptor
fragment: reduce_not_deflate
fragment: Ød1n_373rn4l_fl4r3
FLAG: Ju$7_4_l177l3_7r34$ur3_HUN7@flare-on.com
```

> Mình không có máy macOS/arm64 nên không chạy `click_me` thật. Slice 0 được emulate bằng Unicorn. Slice 1 được phân tích tĩnh, và kết quả được xác nhận qua việc cả 6 MD5 đều khớp và flag giải ra là chuỗi có nghĩa kết thúc bằng `@flare-on.com`.

## Tóm tắt các kỹ thuật

| Lớp | Kỹ thuật / "trò" |
|---|---|
| Tên file | `.doc` giả, thực chất là polyglot |
| COM | Shellcode 16-bit toàn ký tự in được, tự sửa chính nó, giả dạng EICAR (có thể làm AV hoảng) |
| PDF | RC4-40 với user password rỗng; trang khổng lồ nhờ `UserUnit`; text `3 Tr` vô hình; mã **EBCDIC**; ảnh **JBIG2** đặt ngoài trang |
| ZIP | ZipCrypto (`infected`) + nén **Reduce** cổ, không thư viện hiện đại nào hỗ trợ |
| CD | Sector thô 2352 byte (sync/MSF/EDC) giấu trong stream PDF |
| UDF | Không có ISO9660 bridge; dữ liệu giấu trong `LVInfo1` của Implementation Use VD |
| Mach-O | Fat binary 2 slice cùng arm64; `PT_DENY_ATTACH`; chuỗi sinh bằng SHA-0 + XOR; ký tự UTF-8 `Ø` |
| Crystal | Chuỗi stdlib leet-speak; hash giấu dạng nibble `0x8?`; bảng K sinh lúc chạy; key = ⊕SHA-256, RC4 |
| VHD | Footer `conectix` hợp lệ (UniqueID `FLAREONPOLYGLOT!`), không chứa mảnh nào |

## Flag

```
Ju$7_4_l177l3_7r34$ur3_HUN7@flare-on.com
```

*"Just a little treasure hunt."*
