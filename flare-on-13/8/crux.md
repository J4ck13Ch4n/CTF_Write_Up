# FLARE-On 13 — Challenge 8: crux

> *Một extension Chrome, một hàm `check()` gắn lên `globalThis`, và 5,8 MB WebAssembly không
> còn một cái tên nào để đọc.*

## Tổng quan

`8-crux.7z` (mật khẩu `flare`) chứa `extension.zip`; giải nén ra một Chrome extension MV3:

| File | Kích thước | Mô tả |
|---|---|---|
| `manifest.json` | 541 | MV3, CSP `script-src 'self' 'wasm-unsafe-eval'` |
| `popup.html` + `popup.js` | 580 + 769 | ô nhập + nút **Check**, gọi `window.check(input.value)` |
| `wasm_exec.js` | 16.992 | Go JS runtime chuẩn |
| `main.wasm` | **5.836.781** | Go **1.26.5** WebAssembly, bị **garble** obfuscate |

SHA-256 của `ext/main.wasm`: `a39d9bc15609bf40ecc0def4f904e64686d1a7ba705306c59e6e173658a9a96e`.

`check` nhận một chuỗi, trả về flag hoặc đúng một chuỗi lỗi `"Bad input"`. Toàn bộ logic nằm
trong wasm; phần JavaScript chỉ là vỏ. Có ba tầng thật sự:
1. **Cipher ngoài** — base64 → một biến thể AES-256-CBC. KEY/IV là garble literal, không có
   trong file và không có trong bộ nhớ lúc khởi động; chúng chỉ xuất hiện trong heap khi
   `check()` chạy.
2. **Pratt certificate** — cây bằng chứng nguyên tố; mỗi node composite có `A`, witness `B` và
   các con sao cho `A − 1 = ∏ con`.
3. **Payload** — module băm canonical serialization bằng SHA-256, dùng làm khóa AES-256 để
   giải 64 byte ciphertext nhúng sẵn.

*(Các lệnh `python3` dưới đây giả sử đã kích hoạt venv: `source ../.venv/bin/activate` —
xem README mục "Môi trường".)*

```
$ 7z x -y -pflare -o8 8-crux.7z && unzip -o 8/extension.zip -d 8/ext
$ cd 8
$ file ext/main.wasm
ext/main.wasm: WebAssembly (wasm) binary module version 0x1 (MVP)
$ sha256sum ext/main.wasm
a39d9bc15609bf40ecc0def4f904e64686d1a7ba705306c59e6e173658a9a96e  ext/main.wasm
```

## Bản đồ giải quyết

```
ext/main.wasm (Go 1.26.5 + garble, 5,8 MB)
  │
  ├─ export: run / resume / getsp / mem   (không có "check")
  │     └─ check được Go gắn lên globalThis lúc khởi động (syscall/js)
  │
  ├─ f3184 newCipher / f3187 Decrypt  →  AES-256-CBC BIẾN THỂ
  │     └─ round key giữa KHÔNG được InvMixColumns
  │     └─ KEY/IV = garble literal, chỉ xuất hiện trong heap khi check() chạy
  │
  ├─ f3267 parse  →  f3269 verifier  →  f3268 witness  →  f3270 root check
  │     └─ format: leaf `00` (= 2) | composite `01 | nchildren | children | A | B`
  │     └─ root.A phải == N  ←  N KHÔNG có trong file, f3270 dựng lại từ rodata
  │
  └─ payload 64 byte @ 0x36C000
        └─ key = SHA-256(canonical serialization)
        └─ decrypt (cùng custom cipher, cùng IV) → flag + padding 0x06
```

## 1. Nhận diện đối tượng

```bash
$ wasm-objdump -h ext/main.wasm

     Type start=0x0000000e end=0x00000049 (size=0x0000003b) count: 11
   Import start=0x0000004f end=0x000002a0 (size=0x00000251) count: 20
 Function start=0x000002a6 end=0x00000f5f (size=0x00000cb9) count: 3255
    Table start=0x00000f65 end=0x00000f6a (size=0x00000005) count: 1
   Memory start=0x00000f70 end=0x00000f73 (size=0x00000003) count: 1
   Global start=0x00000f79 end=0x00000fa2 (size=0x00000029) count: 8
   Export start=0x00000fa8 end=0x00000fc9 (size=0x00000021) count: 4
     Elem start=0x00000fcf end=0x000028d9 (size=0x0000190a) count: 1
     Code start=0x000028df end=0x0041ccd5 (size=0x0041a3f6) count: 3255
     Data start=0x0041ccdb end=0x00590fa0 (size=0x001742c5) count: 62201
   Custom start=0x00590fa6 end=0x00590fed (size=0x00000047) "producers"
```

Chỉ có 4 export chuẩn của Go runtime, **không có `check`**:

```
 - func[1393] <run>    -> "run"
 - func[1394] <resume> -> "resume"
 - func[1395] <getsp>  -> "getsp"
 - memory[0]           -> "mem"
```

`check` được chương trình Go gắn lên `globalThis` bằng `syscall/js` lúc khởi động:

```js
go.run(result.instance);
initializeExtension();       // popup.js: window.check(input.value)
```

Dấu hiệu garble:

```bash
$ strings -a ext/main.wasm | grep -oE 'go1\.[0-9]+\.[0-9]+' | sort -u
go1.26.5

$ python3 - <<'PY'
w = open('ext/main.wasm','rb').read()
for s in [b'Bad input', b'flare-on.com', b'check']:
    print(s, w.find(s))
PY
b'Bad input' -1
b'flare-on.com' -1
b'check' 4313967          # tên dùng để đăng ký global, không phải literal lỗi
```

Tên hàm bị thay bằng hash; literal bị mã hoá. Cách làm việc: patch bảng export để gọi trực
tiếp các hàm nội bộ (`scripts/patch_exports.py` → `work/main_patched.wasm`), rồi gọi từ Node
theo ABI của Go/wasm.

## 2. Tầng ngoài: base64 + AES-256-CBC biến thể

### 2.1 Mô hình cipher

Gọi trực tiếp `newCipher` (`f3184`) và `Decrypt` (`f3187`) trên wasm đã patch cho thấy cấu
trúc AES quen thuộc: S-box AES, `InvShiftRows`, `InvMixColumns`. Nhưng có một chỗ lệch:

```
Decrypt(C):
    s = C ⊕ rk[14]
    for r = 13 .. 1:
        s = InvShiftRows(s)
        s = InvSubBytes(s)
        s = s ⊕ rk[r]
        s = InvMixColumns(s)
    s = InvShiftRows(s)
    s = InvSubBytes(s)
    s = s ⊕ rk[0]
```

`rk[0..14]` là key schedule **AES-256 tiêu chuẩn** mở rộng từ KEY. Điểm sai là: AES-256
"equivalent inverse cipher" chuẩn dùng `InvMixColumns(rk[r])` cho các vòng giữa; module
**không** biến đổi round key. Vì vậy `Decrypt` không phải AES giải mã chuẩn, và `Encrypt` chỉ
là **nghịch đảo của đúng hàm này** — không phải AES mã hoá chuẩn. Dùng `pycryptodome` hay
`openssl enc -aes-256-cbc` sẽ ra ciphertext sai hoàn toàn.

```python
def encrypt_block(block):
    s = _ark(block, 0)                 # undo ARK(rk[0])
    s = _sub_bytes(s)                  # undo InvSubBytes
    s = _shift_rows(s)                 # undo InvShiftRows
    for r in range(1, NR - 1):         # r = 1 .. 13
        s = _mix_columns(s)            # undo InvMixColumns
        s = _ark(s, r)                 # undo ARK(rk[r])
        s = _sub_bytes(s)
        s = _shift_rows(s)
    s = _ark(s, NR - 1)                # undo ARK(rk[14])
    return s
```

```bash
$ python3 scripts/challenge_cipher.py
# cipher model self-test OK (encrypt/decrypt round trip)

$ python3 scripts/check_roundkeys.py
# rounds field      : 14
# slice1 == slice2  : True
# MATCH with standard AES-256 key expansion: True
```

### 2.2 KEY/IV đến từ đâu

```
KEY = cabeba7ad156801d1c82381c7cb8a3c406ae2c3cd168a96cd8373684cdbf8723
IV  = 5ff26040c4c20b9f2ffdefa7ecf65d91
```

Chúng **không** nằm trong `main.wasm` và cũng không nằm trong bộ nhớ lúc khởi động — garble
đã mã hoá literal và chỉ giải khi `check()` chạy:

```python
w = open('ext/main.wasm','rb').read()
key = bytes.fromhex('cabeba7a...')
iv  = bytes.fromhex('5ff26040...')
print(w.find(key), w.find(iv))        # -1 -1
```

Kết quả tương tự (−1, −1) với dump linear memory lấy ngay sau khi Go runtime khởi động:
garble chỉ giải literal khi `check()` chạy. Sau một lần gọi `check()`, dump toàn bộ linear
memory sẽ thấy chúng trong heap:

| Hằng số | Linear address (post-check dump) |
|---|---|
| KEY (32 byte) | `0x336C29` (ổn định; có thêm bản sao trong heap) |
| IV (16 byte) | `0x3591E8` (ổn định; có thêm bản sao trong heap) |

Tái lập bằng dump harness (dùng chính certificate dựng ở §6):

```bash
$ B64=$(python3 - <<'PY'
import sys, base64
sys.path.insert(0, 'scripts')
import challenge_cipher as cc
from solve_crux import derive_n, build_node, serialize
n, _ = derive_n()
pt = serialize(build_node(n))
print(base64.b64encode(cc.cbc_encrypt(cc.pkcs7_pad(pt))).decode())
PY
)
$ node scripts/dump_after_check.cjs "$B64" /tmp/opencode/crux_mem.bin
$ python3 - <<'PY'
mem = open('/tmp/opencode/crux_mem.bin','rb').read()
print('KEY:', mem[0x336c29:0x336c29+32].hex())
print('IV :', mem[0x3591e8:0x3591e8+16].hex())
PY
KEY: cabeba7ad156801d1c82381c7cb8a3c406ae2c3cd168a96cd8373684cdbf8723
IV : 5ff26040c4c20b9f2ffdefa7ecf65d91
```

Bước xác nhận cuối cùng không phải là "khớp hex" mà là **module thật chấp nhận input do mô
hình tạo ra**: ciphertext 3.904 byte (244 block) được `check()` giải mã và parse đúng thành
cây ở §6. Nếu sai một bit trong model/key/IV, plaintext sẽ hỏng và kết quả là `Bad input`.

## 3. Định dạng certificate

Plaintext sau khi giải mã là một cây nhị phân. Hàm parse `f3267` đọc theo tag 1 byte:

| Tag | Ý nghĩa | Payload |
|---|---|---|
| `00` | leaf | không có — leaf **luôn** là số nguyên tố `2` |
| `01` | composite | `u32 nchildren`, rồi `n × (u32 len + bytes)`, rồi `u32 lenA + A_le`, `u32 lenB + B_le` |

Trong đó `A_le` và `B_le` là biểu diễn **little-endian tối thiểu** (không zero-pad); `A` là
số nguyên tố cần chứng minh; `B` là witness. Các con được serialize trước, theo thứ tự
**không giảm** theo `A` (verifier kiểm tra). Một leaf là đúng 1 byte `00`; không có trường
value.

Ví dụ certificate nhỏ nhất cho `A = 5`: `5 − 1 = 2 × 2`, witness nhỏ nhất là `B = 2`:

```
01 02000000  01000000 00  01000000 00  01000000 05  01000000 02
│  │         │        │   │        │   │        │   │        │
│  │         len=1    leaf len=1    leaf len=1    5   len=1    2
│  nchildren=2
│ tag composite
```

25 byte:

```
01020000000100000000010000000001000000050100000002
```

Certificate của `N` (§6) dài **3.891 byte**; sau PKCS#7 pad thành 3.904 byte = 244 block.

## 4. Bộ kiểm tra Pratt

### 4.1 Toán học

Định lý Lucas (dạng Pratt certificate): để chứng minh `A` nguyên tố, chỉ ra

- phân tích `A − 1 = q₁ q₂ … q_k` thành các số nguyên tố (kể cả bội), và
- witness `B` sao cho `B^(A−1) ≡ 1 (mod A)` và `B^((A−1)/q_i) ≠ 1 (mod A)` với mọi ước
  nguyên tố `q_i` của `A−1`.

Khi đó `A` là nguyên tố. Mỗi `q_i > 2` lại được chứng minh đệ quy; đáy là `2`. Verifier chỉ
việc đi cây và tính luỹ thừa — chi phí kiểm tra rẻ, còn chi phí *tìm* certificate là của
người giải.

### 4.2 Các ràng buộc trong wasm

| Hàm | Vai trò |
|---|---|
| `f3267` | parse binary → cây node có type |
| `f3269` | verifier đệ quy: type switch, thứ tự con, tích `A−1` |
| `f3268` | kiểm tra witness `B` bằng luỹ thừa modulo |
| `f3252` | bytes little-endian → `big.Int` |
| `f3254` | `Cmp` hai `big.Int` |
| `f3251` | `NewInt` |

Type switch dựa trên itab/type hash:

| Node | itab | type hash |
|---|---|---|
| leaf (giá trị 2) | `0x4EF40` (323.392) | `0xB49D0978` (3.030.190.456) |
| composite | `0x4EF60` (323.424) | `0x083C733B` (138.179.387) |

Các điều kiện verifier thực sự thi hành:

1. **Leaf = 2.** Không có cách khai báo leaf khác.
2. **Thứ tự con.** `f3269` so sánh `Cmp(current, previous) < 0` và reject; các con phải
   không giảm.
3. **Đầy đủ factorization.** Tích các giá trị con (leaf = 2, composite = `A` của con) phải
   bằng `A − 1`.
4. **Witness.** `B^(A−1) ≡ 1` và `B^((A−1)/q) ≠ 1` cho mọi con `q`.
5. **Witness nhỏ nhất.** Vòng lặp thử `k = 2 … B−1`; nếu tồn tại `k < B` cũng thoả điều kiện
   witness thì reject. Đây chính là "least primitive root".
6. **Root = N.** So sánh ở `f3270`, sau khi verifier đã pass (xem §5).

### 4.3 Negative tests

Mỗi biến thể được serialize bằng cùng format, encrypt bằng cipher ở §2 rồi đưa vào
`check()` thật:

```bash
$ python3 scripts/probe_variants.py
```

```
variant        bytes    check() result
------------------------------------------------------------------------
canonical      3891     <FLAG>
leaf_val       4971     Bad input  (518 ms)
desc           3891     Bad input  (511 ms)
rootB2         3891     Bad input  (524 ms)
rootB4         3891     Bad input  (622 ms)
rootAplus2     3891     Bad input  (529 ms)
childAplus2    3891     Bad input  (2825 ms)
dropchild      748      Bad input  (3713 ms)
extra_leaf     3896     Bad input  (7681 ms)
other_5        25       Bad input  (512 ms)
other_65537    97       Bad input  (529 ms)
other_1000003  319      Bad input  (523 ms)
```

| Biến thể | Thay đổi | Kết quả |
|---|---|---|
| `leaf_val` | leaf `00` + `u32(1)` + `02` | `Bad input` |
| `desc` | đảo thứ tự con ở mọi node | `Bad input` |
| `rootB2` | witness gốc `B = 2` | `Bad input` |
| `rootB4` | witness gốc `B = 4` | `Bad input` |
| `rootAplus2` | `A` gốc `= N + 2` | `Bad input` |
| `childAplus2` | một con `A += 2` | `Bad input` |
| `dropchild` | bỏ một leaf | `Bad input` |
| `extra_leaf` | thêm một leaf | `Bad input` |

`rootB2`/`rootB4` bị loại vì `2` và `4` không phải primitive root nhỏ nhất mod `N`
(`4 = 2²` nên `4^((N−1)/2) = 1`, fail điều kiện với `q = 2`). `desc` bị loại ngay ở phép so
sánh thứ tự. `rootAplus2`/`childAplus2` fail phép nhân `A−1`. `dropchild`/`extra_leaf` fail
cả cấu trúc lẫn tích. Các input `.b64` được script ghi vào `work/probe/`.

## 5. N — mục tiêu 256-bit

### 5.1 Không có trong file

`N` không xuất hiện dưới dạng byte trong `main.wasm`, cũng không có trong memory lúc startup.
Nó được `f3270` **dựng lại trên stack** mỗi lần kiểm tra. Tìm chuỗi/hex trực tiếp đều thất
bại; đây là lý do phải đọc code chứ không thể `strings`.

### 5.2 `f3270` dựng N

Trong block `B454` của `f3270`:

```
B := mem[0x469F7 : 0x469F7+32]      ; memory.copy dst=sp+240, src=289271
A := mem[0x4EFA0 : 0x4EFA0+32]      ; memory.copy dst=sp+672, src=323488

g3 := u64[0x20ABA0]                 ; 0x3bdfe0e3eb80a09e
g4 := u8 [0x20ABA8]                 ; 0x45
p  := u64[0x20ABB0]                 ; 0x20a6a0
p  := u64[p+112]                    ; 0x209b80
g5 := u8 [p+39]                     ; 0xE3

; pre-adjust 7 byte của B
B[28] ^= 0x8a
B[ 6] ^= g5
B[26] -= g3 >> 56
old7  = B[7]
B[ 7]  = old7 + 15
B[14] -= g4
B[ 4] += 15
B[ 5] ^= (g3 >> 24) & 0xff
B[ 7]  = old7 + g4 + 15

; 16 cặp hoán đổi, i = 0, 2, ..., 30
for i in range(0, 32, 2):
    a0, a1 = A[i], A[i+1]
    k      = i + (a0 ^ a1)
    x      = B[a0] - k
    y      = B[a1] - k
    B[a0]  = y - 85
    B[a1]  = x - 85
```

### 5.3 Chứng minh bằng `derive_n.py`

```bash
$ python3 scripts/derive_n.py
```

```
wasm                : ext/main.wasm
B blob @0x469F7     : 61e20712920aa233bc316ccb233c9f65faf5275bdacf7ada331adf2e31df8963
A table @0x4EFA0    : 1508180608191f19081a1a03091f0c020b021104140810071f02100a11131b13
g3=0x3bdfe0e3eb80a09e  g4=0x45  g5=0xe3
g5 pointer chain    : 0x20a6a0 -> 0x209b80
N bytes (LE)        : 61e230c979e1be78551b7c44963c5a65e3e827b3b04a7adacc029a37bbdf89d3
N                   : 0xd389dfbb379a02ccda7a4ab0b327e8e3655a3c96447c1b5578bee179c930e261
N (decimal)         : 95681613235744740119807961018865688051340183696570761153419351987106658443873
N bit length        : 256
```

Script không hard-code `N`; nó chạy đúng permutation ở trên từ dữ liệu trong wasm (parse toàn
bộ 62.201 data segment để map địa chỉ). `N` là số nguyên tố 256-bit, và

```
N − 1 = 2⁵ · 1777 · 117013415621 · 14379885447462257985539844615548173977763374139182362877999463
```

(ước cuối là số nguyên tố 204-bit).

### 5.4 Root check

`f3270` so `root.A` với `N` **sau khi** verifier pass. Vì vậy một Pratt certificate **hợp lệ
hoàn toàn** cho một số nguyên tố khác vẫn bị loại (ba dòng cuối của `probe_variants.py` ở §4.3):

```
other_5        25       Bad input
other_65537    97       Bad input
other_1000003  319      Bad input
```

Với `P = 5`, cây `(5, B=2, [2,2])` qua được `self_check` của chúng ta (đúng toán học, đúng
thứ tự, đúng witness nhỏ nhất) nhưng vẫn `Bad input` — khác biệt duy nhất là `5 ≠ N`. Đây là
bằng chứng thực nghiệm cho root check.

## 6. Dựng certificate

Thuật toán (`scripts/solve_crux.py`):

```python
@lru_cache
def build_node(a):
    if a == 2:
        return (2, None, ())
    fac = factor(a - 1)                      # Miller-Rabin + Pollard rho
    children = sorted((build_node(q) for q in fac), key=lambda n: n[0])
    witness = least_primitive_root(a, set(fac))
    return (a, witness, tuple(children))
```

- `factor` là Miller-Rabin + Pollard rho thuần Python, có cache; không phụ thuộc sympy.
- `least_primitive_root` thử `g = 2, 3, ...` cho đến khi thoả điều kiện Lucas.
- `children` sắp xếp tăng dần theo `A`, giữ bội số (nếu `2⁵` thì có 5 leaf `2`).

Tự kiểm tra từng node trước khi serialize (điều kiện giống hệt verifier):

```python
def self_check(node):
    a, b, children = node
    if a == 2:
        assert children == ()
        return a
    product = 1
    for c in children:
        product *= self_check(c)
    assert product == a - 1
    assert is_witness(a, b, children)
    for k in range(2, b):
        assert not is_witness(a, k, children)   # B phải nhỏ nhất
    return a
```

Kết quả: **357 node**, độ sâu **11 cạnh** (12 tầng), **50** số nguyên tố khác nhau (bao gồm
2), witness gốc `B = 3`, serialization dài **3.891 byte**.

## 7. Lời giải

```bash
$ python3 scripts/solve_crux.py
```

```
[*] deriving N from ext/main.wasm ...
    N = 0xd389dfbb379a02ccda7a4ab0b327e8e3655a3c96447c1b5578bee179c930e261  (256 bits)
[*] factoring N-1 and building the Pratt certificate ...
    certificate: 3891 bytes, 357 nodes, 50 distinct primes (incl. 2), root B=3
[*] encrypting with the challenge cipher ...
    plaintext 3891 bytes -> ciphertext 3904 bytes
[*] calling the real wasm check() (fresh Node process) ...
    check() = <FLAG>
[*] local payload cross-check (SHA-256 of serialisation + challenge IV) ...
    key      = c9c3e3392c54fa79b313b8f9696539b8838740cafe086e036ba888ac1e358086
    plaintext= '<FLAG>'

FLAG: <FLAG>
[*] done in 26.5s
```

Hai lớp kiểm tra độc lập cùng ra một kết quả: (1) oracle thật `check()` trong wasm, (2) giải
payload 64 byte bằng `SHA-256(canonical serialization)` + IV ngoài.

## 8. Tầng cuối: SHA-256 và payload

Sau khi verifier và root check đều pass, module:

1. serialize lại cây theo canonical form (với input của ta, canonical form **chính là** 3.891
   byte đã gửi);
2. tính `SHA-256(canonical)` → đây là khóa AES-256;
3. giải 64 byte payload nhúng sẵn bằng cùng custom cipher, dùng lại IV ngoài;
4. bỏ PKCS#7 padding → flag.

Bằng chứng trong post-check dump:

| Vật thể | Linear address | Giá trị |
|---|---|---|
| digest `SHA-256(serialization)` | `0x336AE8` (ổn định) | `c9c3e3392c54fa79b313b8f9696539b8838740cafe086e036ba888ac1e358086` |
| payload ciphertext (64 byte) | `0x36C000` (ổn định) | `78b95d28…d4491a3c2` |
| flag plaintext | trong heap, **3 bản copy** (địa chỉ thay đổi theo lần chạy) | `<FLAG>` |

Giải payload độc lập:

```python
import hashlib, sys
sys.path.insert(0, 'scripts')
import challenge_cipher as cc
from solve_crux import derive_n, build_node, serialize

n, _ = derive_n()
pt = serialize(build_node(n))                # 3.891 byte canonical
payload = bytes.fromhex(
    '78b95d284fb5a232df1ccc908e10fe1a2d7faa97cc43c2797087f03ad311c512'
    '997cd0e4fb72ca3072c3e2ad0de6232ff619632797e3708ad29b2cdd4491a3c2')

key = hashlib.sha256(pt).digest()
cc.RKS, cc.NR = cc.expand_key(key)          # 32-byte key -> AES-256
raw = cc.cbc_decrypt(payload)               # dùng lại IV = 5ff26040...
print(raw)
```

```
b'<58 byte flag>\x06\x06\x06\x06\x06\x06'
```

58 byte flag + 6 byte padding `0x06`. Khớp tuyệt đối với kết quả `check()` thật.

## 9. Mồi nhử và bẫy

1. **"AES-256-CBC" không phải AES-256-CBC.** Cipher dùng S-box/ShiftRows/MixColumns chuẩn
   nhưng round key giữa không được `InvMixColumns`; `openssl`/`pycryptodome` cho ra ciphertext
   sai. Phải dùng nghịch đảo của đúng hàm `Decrypt` trong module.
2. **KEY/IV không nằm trong file.** Garble mã hoá literal; tìm kiếm tĩnh (kể cả các biến thể
   word-swap/reverse/XOR) đều thất bại. Chúng chỉ xuất hiện trong heap sau khi `check()` chạy.
3. **Bẫy base64 alphabet.** Ở startup memory, `0x36C000` chứa `&` + 63 ký tự đầu của bảng
   base64 chuẩn (bảng `A…Z a…z 0…9 + /` bắt đầu ở `0x36C001`); sau khi `check()` thành công,
   đúng range 64 byte `0x36C000–0x36C03F` được ghi đè bằng payload. Ai quét memory lúc khởi
   động sẽ thấy toàn ký tự base64 và tưởng "không có payload".
4. **Certificate hợp lệ cho số khác vẫn fail.** `P = 5`, `65537`, `1000003` đều qua toán học
   và qua `self_check`, nhưng `root.A` phải đúng `N`. Đây là bẫy lớn nhất: dựng certificate
   đúng thuật toán nhưng sai target.
5. **Witness không phải nhỏ nhất.** `B = 2` hay `B = 4` cho root `N` đều bị reject; không
   đủ để chỉ ra "một primitive root", phải là primitive root **nhỏ nhất** (vòng lặp
   `k = 2..B−1`).
6. **Thứ tự con.** Đảo thứ tự (dù tích vẫn đúng) bị reject bởi `Cmp(current, previous) < 0`.
7. **Leaf có value.** Encode `00` + `u32(1)` + `02` (cùng cây, khác format) bị reject; leaf
   phải đúng 1 byte `00`.
8. **Thiếu/thừa con.** `dropchild`/`extra_leaf` bị reject; tích `A−1` và cấu trúc đều được
   kiểm tra.
9. **Patch verifier không phải đường tắt.** `main_noverify.wasm` (f3269 → return nil) bỏ
   kiểm tra cấu trúc/toán học, nhưng root check vẫn đòi `root.A == N`; và vì payload key là
   `SHA-256(canonical serialization)`, mọi biến thể làm đổi serialization (B=2/4, desc,
   child+2, thiếu/thừa con) đều cho key sai → decrypt/padding hỏng → `Bad input`. Đã kiểm
   chứng: mọi biến thể sai đã thử (B=2/4, desc, child+2, thiếu/thừa con, P=5/65537) đều
   `Bad input` qua `main_noverify.wasm`; chỉ `canonical` trả flag.
10. **"Bad input" là oracle duy nhất.** Không có thông báo lỗi chi tiết; mọi thử nghiệm phải
    dựa trên việc dựng đúng input và so kết quả.

## 10. Bài học

- **Đọc code trước khi tin mô tả.** Hint blog nói cipher thay ShiftRows/viết lại key schedule;
  mô hình đúng lại là "AES-256 với encryption round keys trong equivalent-inverse order". Cả
  hai đều dẫn đến "không dùng AES library", nhưng chỉ công thức đúng mới tạo được input
  được chấp nhận. Kiểm chứng bằng oracle (244 block) quan trọng hơn mọi mô tả.
- **Canonical là một phần của bài toán.** Cùng một cây Pratt, sai thứ tự con / sai encoding
  leaf / witness không nhỏ nhất đều fail. Verifier không chỉ kiểm tra toán học mà còn kiểm
  tra *biểu diễn*.
- **Root check là nơi giấu "target".** `N` không có trong file; nó được dựng từ rodata +
  permutation. Phải trích xuất đúng `N` trước khi mọi phép toán trở nên có nghĩa.
- **Garble không miễn nhiễm với đọc hiểu.** Tên hàm mất, literal mã hoá, nhưng cấu trúc
  điều khiển và các phép toán vẫn đọc được; patch export để gọi nội bộ là cách nhanh nhất
  để lấy oracle.
- **Kiểm tra end-to-end luôn thắng self-check.** `self_check` của ta có thể pass một cây
  "đúng toán học" cho `P = 5`; chỉ khi gọi module thật mới biết root phải là `N`.

## Flag

```
Pr4tt_Pr1M4lItY_C3rt5_4nd_Wa4aA4aAA4aAA4a4a5M@flare-on.com
```

*"Pratt" + "primality" ⇒ chứng thư nguyên tố; "4nd" ⇒ "and" bị bóp méo; "Wa4aA4a" là hài
hước với "WAAA" — đúng kiểu viết flag của Flare-On.*
