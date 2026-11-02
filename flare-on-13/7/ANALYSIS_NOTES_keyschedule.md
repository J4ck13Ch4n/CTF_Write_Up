# FlareCalc — phân tích mô hình mã hoá (đo từ binary, không theo blog)

Ghi lại những gì đã **đo trực tiếp trên `FlareCalc.exe`**, làm nền cho việc dò key schedule.
Mọi phép đo đều reproduce được bằng `scripts/flarecalc_table.py` (`load_entries()` → `[(id, blob), ...]`).

## 1. Bảng ASN.1

- `WIN_CERTIFICATE` @ `0xEEC00` (len 529.568, type 2 = PKCS#7) → `certificates[0]` → 3 cert X.509 giả
  → cert #3 → extension OID `1.3.6.1.4.1.13839.1` → OCTET STRING @ **file `0xEF471`** (526.579 B).
- Bảng: 1.035 record `SEQUENCE { INTEGER id, OCTET STRING blob }`, id 49..65469, đều khác nhau.
- blob len: min 118 (id 9990), median ~434, max 46.500 (id 3821).

## 2. Cấu trúc blob — MÔ HÌNH ĐÃ XÁC MINH

Mỗi blob xen kẽ **1 byte plaintext thật** rồi **1–3 byte rác**; **gap ∈ {2,3,4}**.

| Khẳng định | Bằng chứng |
|---|---|
| Lịch gap **dùng chung cho mọi entry** | Hợp nhất detector trên 1.033 entry cho ra tập vị trí `R` rất sạch, gap đều ∈ {2,3,4} |
| **Keystream riêng từng entry** | 4485 vs 3833: **0/293** vị trí thật chung có byte trùng nhau |
| **Byte rác có `low3` = hằng per-entry** | id 4485: **819/819** byte rác có `low3 = 4`; id 3833: 812/812 → `low3 = 0` |
| **Vị trí "ẩn"** | Byte thật có `low3(pt) == 0` ⇒ `low3(ct) == c` ⇒ **trông y hệt byte rác**, không phát hiện được. id 4485: 384 byte thật, phát hiện 336 ⇒ **48 vị trí ẩn** (≈1/8) |
| Byte thật: `ct[p] = pt[j] ^ ks[j]` | `low3` tại vị trí thật phân bố **đều trên cả 8 giá trị** (đo ở 4485: 47,44,52,44,45,56,48) ⇒ `low3(ct) = low3(pt) ^ low3(ks)` |
| Hằng per-entry `c` ∈ **{0,1,2,4,5,6}** | modal low3 của blob trên 1.034 entry: 0→128, 1→272, 2→120, 4→130, 5→235, 6→148. **Không bao giờ 3 hay 7** |

### Tập vị trí thật `R` (hợp nhất detector, 257 entry "sạch")

```
0, 2, 5, 7, 10, 14, 18, 22, 24, 28, 30, 33, 36, 39, 42, 45, 47, 49, 51, 54, 57,
61, 64, 67, 70, 73, 76, 79, 83, 86, 89, 91, 95, 97, 99, 102, 105, 107, 111, 114,
118, 122, 125, 127, 131, 135, 138, 142, 145, 147, 151, 155, 159, 162, 164, 167,
169, 172, 176, 180, 186, 190, 192, 194, 198, 201, 204, 208, 211, ...
```

- **5 vị trí thật đầu tiên chắc chắn: `0, 2, 5, 7, 10`** (gap 2,3,2,3 không thể chứa vị trí ẩn).
- Chuỗi gap quan sát (`gap-2`): `0,1,0,1,2,2,2,0,2,0,1,1,1,1,1,0,0,0,1,1,2,1,1,1,1,1,1,2,1,1,...`
  — số `2` có thể là gap thật 4 **hoặc** 2 vị trí thật cách nhau 2+2 (vị trí ẩn).

## 3. Những điều ĐÃ LOẠI TRỪ (đừng thử lại)

| Giả thuyết | Kết quả |
|---|---|
| `ks[j] = (state>>16)&0xFF`, `state = state*1103515245+12345` | **Sai**: mô phỏng 3.000 seed × 400 bước ⇒ `low3(ks)` đổi **cả 8 giá trị** ở mọi vị trí shift 0..28 (tức bit 16–18 trôi nhanh, không thể "đóng băng" theo entry) |
| `(ct[real] ^ ct[real+1]) & 7` là `low3(pt)` (byte rác mang low3 keystream) | **Sai**: độ đồng thuận giữa các entry chỉ 0.28 (ngẫu nhiên) |
| Byte rác = chuỗi LCG mod 256 | **Sai**: thử hết 65.536 bộ (A,C) mod 256 trên dãy byte rác ⇒ không khớp |
| `c_e` suy từ `md5(pwd‖id)` (fold ×31/×33, digest[0:4] LE/BE, …) | **Sai**: khớp 11–26% (ngẫu nhiên ~12–17%) |
| `c_e` = hàm đơn giản của `id` (id&7, (id>>k)&7, md5(id), sha256(id), CRC, FNV, djb2, nhân hằng số…) | **Sai**: không vượt ngưừu nhiên |
| Master password nằm trong file (ASCII/UTF-16/XOR-1 byte/số 32-64 bit/float64) | **Sai**: không có hit nào |
| Blog: `i += 1 + (roll%3) + 1` với `roll` LCG `1103515245/12345` | **Vô lý**: `1103515245 % 3 == 0` và `12345 % 3 == 0` ⇒ `roll % 3` **luôn = 0** ⇒ gap luôn 2, trái dữ liệu |
| Blog: password `8675309-88224646-31428571` + lịch gap kiểu blog | **Sai**: lịch gap blog (`0,2,5,8,12,15,17,…`) khác hẳn dữ liệu (`0,2,5,7,10,14,18,…`) |
| Blog: 1.034 entry là "x86-64 code stub" | id **3821** là **46.500 byte code x86-64 THẬT** (capstone giải 100%, gọi vào `.text` của chính file) ⇒ **mồi**, không phải blob mã hoá |
| Blog: các decoy `FLAG{NICE_TRY}`, `ACCESS DENIED`, `KEY_EXPIRED`, honeypot `WM_COPYDATA`/`0xC3F12A8B`, beacon hostname/username/uptime nằm trong PE | **Sai**: **không có** trong file ⇒ chúng nằm trong bảng đã mã hoá |

## 4. Dữ liệu còn dùng được

- Blog cho node path (chỉ để đối chiếu): `52090 → 54272 → 44269 → 60903 → 3394 → 5295 → …` (6140, 53282, 34912 **không** có trong bảng này ⇒ blog có ít nhất 1 sai số).
- Blog cho khóa 32 byte: `670daa0ff05e7d85472eeb55a716a7b88d63019c27ee22ea447fd4fde87c013d`.
- Blog cho flag (40 byte — khớp đúng plaintext của entry 9990): *(không ghi lại ở đây; xem
  `7/FlareCalc.md`, mục **Flag** cuối bài)*.
- Stall loop (từ blog) ⇒ template chứa byte pattern `44 24 10` (`mov dword [rsp+10],0` = `C7 44 24 10 00 00 00 00`; `add dword [rsp+10],eax` = `01 44 24 10`), `3D 40 42 0F 00` (`cmp eax,0F4240h`), `2D E0 E6 4A 6A` (`sub eax,6A4AE6E0h`).

## 5. Hướng dò key schedule (đề xuất)

1. **Oracle mẫu lệnh** (xem `scripts/brute_seed.c`): với seed 32-bit `s0`, dựng keystream, kiểm tra `blob[p] ^ ks[k+o]` khớp `44 24 10` với `p` = vị trí thật quan sát được (index `k`) và `o` = lệch chỉ số do vị trí ẩn (`0 ≤ o ≤ k/8+2`). Xác suất false-positive ≈ `2400 × 2^-24` rất nhỏ.
2. Khi tìm được seed của 1 entry: giải mã toàn bộ entry → **phải là code x86-64 hợp lệ 100%** (capstone) ⇒ xác nhận tuyệt đối, đồng thời biết chính xác các vị trí ẩn và template chung.
3. Khi biết (vị trí blob, chỉ số keystream) của mẫu, các entry còn lại chỉ cần kiểm 1 vị trí ⇒ rất nhanh.
4. **PRNG gap**: brute-force state 32-bit với `gap = 2 + ((state>>S) % 3)` (S ∈ {0,8,16,24}) sao cho tập vị trí sinh ra **chứa toàn bộ `R`**; seed của PRNG này có thể suy ra từ password.
