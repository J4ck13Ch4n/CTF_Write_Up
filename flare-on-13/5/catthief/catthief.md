# FLARE-On 13 — Challenge 5: catthief

**Flag:** `th3r3_b3_tr34sure_1n_th4t_pc4p@flare-on.com`

> *"One of our stray laboratory felines just pilfered classified contraband from the server room... Recover what the cat dragged out."*

## Tổng quan

`5-catthief.7z` (mật khẩu `flare`) gồm hai file:

| File | Mô tả |
|---|---|
| `catthief.exe` | PE32+ x64, viết bằng **Rust** (ureq, rustls, ring, hashbrown) |
| `capture.pcapng` | 2810 gói tin, ~15 MB |

Mục tiêu: khôi phục những gì con mèo đã exfil ra ngoài.

## 1. Phân tích pcap

Gần như toàn bộ lưu lượng là HTTP thuần từ `192.168.56.103` tới `192.168.56.102:8080`. Server là `BaseHTTP/0.6 Python/3.8.10`:

```
POST /exfil  (264 B)       -> 200, body 36 B
POST /exfil  (3 121 086 B) -> 200, body 37 B
POST /exfil  (2 736 058 B) -> 200, body 40 B
POST /exfil  (3 061 432 B) -> 200, body 36 B
POST /exfil  (3 079 606 B) -> 200, body 40 B
POST /exfil  (2 842 789 B) -> 200, body 0 B
```

Mọi body đều ở dạng nhị phân. Có hai quan sát quan trọng:

* Các request đều bắt đầu bằng cùng một chuỗi byte, và response cũng vậy. Điều đó cho thấy **mọi message dùng chung một keystream**.
* XOR request #0 với từng response cho ra chuỗi gần như đọc được: `c:\Us%rs\flare\Desktop\important.jpg`, ... Vậy response là **đường dẫn file** mà server ra lệnh cho client gửi lên.

## 2. Reverse `catthief.exe`

Tôi decompile bằng Ghidra headless. Trong hàm main (`0x1400029aa`) có các chuỗi `READY`, `http://192.168.56.102:8080/exfil`, `ERROR` và `src\compress.rs`.

### 2.1 Mã hoá: RC4

```c
local_291 = *(u128*)0x1400c9010;           // 16 byte
local_281 = 0x0407576c41004a6c;            // 8 byte
local_279 = 0x07;                          // 1 byte
for (i = 0; i < 0x19; i++) key[i] ^= 0x33;
rc4_ksa(&st, key);                         // FUN_1400052e2 (keylen = 0x19, i % 25)
rc4_crypt(&st, buf, len);                  // FUN_140005281
```

Giải XOR 0x33 ra khoá **`i11_b3_p1und3r1n_y3r_d474`** ("I'll be plunderin' yer data"). Mỗi message được KSA lại từ đầu, và đó là lý do các message dùng chung keystream.

### 2.2 Nén: canonical Huffman (`compress.rs`)

Trước khi mã hoá, dữ liệu được nén:

1. Đếm tần suất từng byte (HashMap của hashbrown).
2. Dựng cây Huffman bằng binary heap để có độ dài mã cho 256 symbol.
3. Sắp các cặp `(sym, len)` theo `(len, sym)` rồi gán mã canonical: `code = (code + 1) << (len - prev_len)`.
4. Ghi ra một **chuỗi ký tự `'0'/'1'`** (`FUN_1400053fe` ghi từng bit thành `'0'`/`'1'`), sau đó pack thành byte:

```
[11 bit]  số entry của bảng độ dài (= 256)
[32 bit]  trường "độ dài" (không đáng tin, xem bên dưới)
[256 × 8 bit] độ dài mã của symbol 0..255
[...]     bitstream Huffman, pad 0 cho đủ byte
```

Tôi kiểm chứng với message đầu tiên. Bảng độ dài là `A:3 D:2 E:3 R:2 Y:2`, và bitstream `01 111 110 00 10` giải ra đúng **`READY`**.

Trường 32 bit không phải độ dài thật (với `READY` nó bằng 2). Vì vậy tôi giải hết bitstream, rồi cắt ở marker `FF D9` cuối cùng để bỏ các symbol rác sinh ra từ bit padding.

## 3. Khôi phục file

`solve.py`: ghép TCP stream → tách body HTTP → RC4 → giải Huffman.

```
$ python solve.py
first message: b'READY'
C:\Users\flare\Desktop\important.jpg      -> important.jpg      3123324
C:\Users\flare\Desktop\anothercat.jpg     -> anothercat.jpg     2738892
C:\Users\flare\Desktop\yetanothercat.jpg  -> yetanothercat.jpg  3065529
C:\Users\flare\Desktop\catcatcat.jpg      -> catcatcat.jpg      3084399
C:\Users\flare\Desktop\myfavoritecat.jpg  -> myfavoritecat.jpg  2844616
```

Kết quả là năm ảnh JPEG 2816×1536, đều là mèo hải tặc. Trong `catcatcat.jpg`, trên cuộn giấy da đặt cạnh rương có viết flag:

```
th3r3_b3_tr34sure_1n_
th4t_pc4p@flare-on.com
```

## Flag

```
th3r3_b3_tr34sure_1n_th4t_pc4p@flare-on.com
```
