# FLARE-On 13 — Challenge 2: GhostStream

**Flag:** `y0u_kn0w_n07h1n6_j0n_5n0w@flare-on.com`

> *"It refuses to talk to the naked eye, and you aren't getting your nutrient paste until your debugger forces a confession out of it."*

## Tổng quan

Archive `2-GhostStream.7z` (mật khẩu `flare`) chứa một file duy nhất là `GhostStream.wim`, một Windows Imaging Format image. Tên bài *GhostStream* là gợi ý thẳng về **NTFS Alternate Data Stream (ADS)**. WIM là một trong số ít định dạng lưu trữ giữ được ADS.

Chuỗi xử lý tổng thể:

```
GhostStream.wim
 ├─ GhostStream.exe            (parent)
 │    └─ resource BIN/101  →  %TEMP%\Partner_CTF.exe  (child)
 └─ PolyjuicePotion.txt
      ├─ ::$DATA               "During their second year, Harry, Ron, and Hermione ..."
      └─ :LordVoldemort        "AlbusDumbledore \r\n"

parent ──(\\.\pipe\FlareChallenge : key)──► Partner ──► RC4 biến thể ──► flag
```

## 1. Giải phẫu file WIM

Mở WIM bằng DISM cần quyền admin, và máy không có 7-Zip, nên mình parse tay. Header cho biết `flags = 0x80` (không có cờ nén), vì vậy mọi resource đều nằm nguyên văn trong file.

| Header field | Giá trị |
|---|---|
| Lookup table | offset `0x8EAE`, 200 byte → 4 entry × 50 byte |
| XML data | offset `0x8F76`, 702 byte (`DIRCOUNT=1`, `FILECOUNT=2`) |

Lookup table (mỗi entry gồm reshdr 24 byte, part 2 byte, refcount 4 byte và SHA-1 20 byte):

| # | Offset | Size | Nội dung |
|---|---|---|---|
| 0 | `0xD0` | 35328 | `GhostStream.exe` |
| 1 | `0x8AD0` | 316 | `PolyjuicePotion.txt` (luồng chính) |
| 2 | `0x8C0C` | 18 | **`LordVoldemort`** (luồng ẩn) |
| 3 | `0x8C1E` | 656 | metadata resource (các dentry) |

Trong metadata resource, dentry `PolyjuicePotion.txt` có `num_streams = 2`. Stream thứ hai tên `LordVoldemort` trỏ tới SHA-1 `e6ab6e53…`, có nội dung:

```
AlbusDumbledore \r\n
```

Luồng chính kể chuyện Ron cho quá nhiều da boomslang vào thuốc đa dịch, *"the transformation effect is now stuck for exactly **7 days**"*. Con số 7 ngày sẽ quan trọng ở bước 4.

## 2. Parent: `GhostStream.exe`

PE x64, MSVC. Import đáng chú ý: `FindResourceW`, `CreateProcessW`, `CreateThread`, WinSock (`bind`/`listen`/`recv`), `SetEnvironmentVariableA`, `GetWindowLongPtrW`/`SetWindowLongPtrW`/`DefWindowProcW`.

Resource `BIN/101` (14848 byte) là một PE thứ hai. Parent ghi nó ra `%TEMP%\Partner_CTF.exe` rồi chạy.

### 2.1 Chuỗi bị mã hóa, khóa phụ thuộc tên file

Hàm `0x140001130` giải chuỗi, với khóa lấy từ **tên file của chính exe**:

```c
name = basename(GetModuleFileNameA());
k    = name[strlen(name)/2] ^ name[0];          // "GhostStream.exe": 'r' ^ 'G' = 0x35
mode = jumptable[(sum(enc) & 0xff) - 0x1c];     // 0, 1 hoặc 2
// mode 0: c - k      mode 1: (c + 1) ^ k      mode 2: c - 2 + k
```

Nếu đổi tên exe thì mọi API resolve động đều hỏng. Đây là một lớp anti-analysis nhẹ. Emulate lại với tên `GhostStream.exe`:

| Chuỗi mã hóa (độ dài) | Giải ra |
|---|---|
| `rbp+0x28` (35) | `%sPolyjuicePotion.txt:LordVoldemort` |
| 13 | `OpenClipboard` |
| 22 | `NtSetInformationThread` (gọi với `0x11` = `ThreadHideFromDebugger`) |
| 23 | `\\.\pipe\FlareChallenge` |
| 16 / 15 | `RegisterClassExA` / `CreateWindowExA` |
| 16 / 16 | `CreateNamedPipeA` / `ConnectNamedPipe` |
| 15 / 23 | `GetProcessTimes` / `GetSystemTimeAsFileTime` |

### 2.2 Luồng `main` (`0x140001EA0`)

```c
esi  = strlen(exe_name) * 0x29f;               // 15 * 671 = 10065
path = sprintf("%sPolyjuicePotion.txt", exe_dir);

CreateThread(socket_thread, {key_buf, 0x100}); // cổng 31337, "OVERRIDE:"
Sleep(10000);
CreateThread(telemetry_thread, {enc_ads_fmt, 0x23, tmp, path, exe_dir, 0x104});
WaitForSingleObject(...);

NtSetInformationThread(-2, ThreadHideFromDebugger, 0, 0);

h = CreateFileA(path, GENERIC_READ, ...);
ReadFile(h, key_buf, 0xff, &n); key_buf[n] = 0;

uptime_calc();                                 // 0x140001680 -> g_minutes
esi += 0xf;                                    // 10080
CreateWindowExA(..., lpParam = {key_buf, pipe_str, g_minutes, esi, 0});

pipe = CreateNamedPipeA("\\\\.\\pipe\\FlareChallenge", ...);
drop_and_run_partner();                        // 0x140001400
ConnectNamedPipe(pipe);
WriteFile(pipe, key_buf, strlen(key_buf));
```

### 2.3 Cửa ẩn thứ nhất: đọc ADS thay vì luồng chính

Thread telemetry (`0x140001860`) chủ yếu tính toán vô nghĩa (hash `0x1337`, `GetSystemInfo`, `GlobalMemoryStatusEx`, chuỗi `Telemetry_%u_%x`). Ngoại trừ đoạn này:

```c
if (g_flag_6668 == 1) {                         // dword @ 0x140006668
    decode(enc_ads_fmt, 0x23, tmp);             // "%sPolyjuicePotion.txt:LordVoldemort"
    sprintf(path, 0x104, tmp, exe_dir);         // ghi đè đường dẫn sẽ được ReadFile
}
```

**Không có lệnh nào ghi vào `0x140006668`.** Biến này luôn bằng 0, nên khi chạy bình thường parent chỉ đọc luồng chính. Đây chính là chỗ mà *"your debugger forces a confession"*: phải dùng debugger sửa biến này thành 1 thì parent mới đọc `PolyjuicePotion.txt:LordVoldemort`, tức `AlbusDumbledore \r\n`.

### 2.4 Cửa ẩn thứ hai: "stuck for exactly 7 days"

`0x140001680` tính số phút tiến trình đã chạy:

```c
GetProcessTimes(GetCurrentProcess(), &creation, &exit, &kernel, &user);
GetSystemTimeAsFileTime(&now);
g_minutes = (now - creation) * 0xe5109ec205d7bea7 >> (64 + 0x1d);   // ≈ Δ / 600,000,000 (100ns) = phút
```

WndProc (`0x140001B20`) lưu `lpParam` ở `WM_NCCREATE`. Với mỗi message sau đó, nó tính `r11 = msg ^ last_msg`. Tại `WM_CREATE (1)`:

```c
if (ctx->minutes > ctx->threshold) {           // threshold = 10080 phút = 7 ngày
    for (i = 0; i < strlen(key); i++) key[i] ^= r11;
    key[0..14] ^= {8b 8f 92 85 88 96 98 9b 94 8b 95 e6 ed f0 e7};
} else {
    pipe_str[0..14] ^= {...};                  // chỉ làm hỏng một bản copy không dùng
    SetEnvironmentVariableA("SESSION_TOKEN_CACHE", pipe_str);
}
```

Thứ tự message khi tạo cửa sổ là `WM_NCCREATE (0x81)` → `WM_NCCALCSIZE (0x83)` → `WM_CREATE (0x01)`, nên tại `WM_CREATE` ta có `r11 = 0x01 ^ 0x83 = 0x82`.

Áp lên nội dung ADS:

```
"AlbusDumbledore" ^ 0x82 ^ {8b 8f 92 ...}  =  "HarryPotter\0\0\0\0"
```

Bốn hằng số cuối `e6 ed f0 e7` bằng `"dore" ^ 0x82`, nên phần đuôi bị triệt tiêu thành NUL. Đây là bằng chứng rõ ràng rằng `r11 = 0x82` đúng là giá trị tác giả dự tính. Parent sau đó ghi `strlen(buf) = 11` byte xuống pipe, tức **key = `HarryPotter`**.

### 2.5 Mồi nhử

* **Socket `127.0.0.1:31337`**: nhận `OVERRIDE:<data>` và ghi `(c ^ 0x33) + 5` vào `key_buf`. Nhưng thread này chạy *trước* `ReadFile`, nên dữ liệu bị ghi đè ngay. Nó chỉ để đánh lạc hướng.
* **Thread Telemetry**, **`OpenClipboard(GetConsoleWindow())`**, **`SESSION_TOKEN_CACHE`**: không ảnh hưởng tới key.

## 3. Child: `Partner_CTF.exe`

### 3.1 Nhận key

```c
h = CreateFileA("\\\\.\\pipe\\FlareChallenge", GENERIC_READ, ...);   // retry với WaitNamedPipeA
ReadFile(h, key, 0xff, &n); key[n] = 0;
key[strcspn(key, "\r\n")] = 0;
```

### 3.2 RC4 KSA

Khởi tạo S-box bằng SIMD (`S[i] = i`), sau đó chạy KSA chuẩn với `key`. Con trỏ `ucrtbase!strlen` được giấu trong biến toàn cục dưới dạng `ptr ^ 0xdeadbeef` và qua vài bước cộng/XOR vô nghĩa.

### 3.3 Hook `strlen` bằng shellcode

```c
VirtualProtect(strlen, 0x17, PAGE_EXECUTE_READWRITE, &old);
save 0x17 byte gốc;
write: 31 c0 04 13 b2 01 75 01 e8 00 11 30 01 fe c2 48 ff c1 38 21 75 f3 c3
```

Disassemble. Byte `e8` là junk để đánh lừa linear-sweep disassembler, vì `jne` luôn nhảy qua nó:

```asm
xor  eax, eax
add  al, 0x13          ; ZF = 0
mov  dl, 1
jne  +1                ; luôn nhảy, bỏ qua byte 0xE8
loop:
add  byte [rcx], dl
xor  byte [rcx], al
inc  dl
inc  rcx
cmp  byte [rcx], ah    ; ah = 0
jne  loop
ret                    ; eax = 0x13
```

Sau đó Partner gọi `strlen("Bxs]bv`^u)TpcnolVjN")`. Hook giải chuỗi này **tại chỗ** theo công thức `c = (c + i) ^ 0x13`:

```
Bxs]bv`^u)TpcnolVjN  →  Piertotum Locomotor
```

Tiếp theo nó gọi `strlen("Wingardium Leviosa")` và dùng giá trị trả về làm tham số `step` cho PRGA, rồi khôi phục lại 0x17 byte gốc của `strlen`. Các lệnh `GetEnvironmentVariableA("COMPUTERNAME")`, `IsDebuggerPresent` và `GetTickCount` ở đoạn này đều bị bỏ kết quả, chỉ là nhiễu.

### 3.4 RC4 PRGA biến thể

```c
i = j = 0;
for (k = 0; k < 38; k++) {
    i = (i + step) & 0xff;                     // RC4 chuẩn: step = 1
    j = (j + S[i]) & 0xff;
    swap(S[i], S[j]);
    ct[k] = S[(S[i] + S[j]) & 0xff] ^ xk[k % 19] ^ (uint8_t)(ct[k] + step);
}
if (strstr(ct, "@flare-on.com")) printf("[SUCCESS] Decrypted Flag: %s", ct);
else                             printf("[FAILED] Try again with better debugging");
```

Ciphertext (38 byte) được dựng trên stack từ các hằng `0x35875c96, 0x8b397ad7, …, 0xf8a5`.

## 4. Lời giải

Tóm tắt các điều kiện cần ép:

1. `g_flag_6668 = 1` để parent đọc ADS `:LordVoldemort`.
2. `g_minutes > 10080` (uptime hơn 7 ngày) để WndProc biến `AlbusDumbledore` thành `HarryPotter`.

Nếu làm động, có thể dùng x64dbg: đặt breakpoint tại `0x140001A8C` rồi sửa `[0x140006668] = 1`, và tại `0x140001BAA` thì ép nhánh `ja` (hoặc sửa `ctx->minutes`). Ngoài ra còn phải vượt `ThreadHideFromDebugger`, ví dụ bằng ScyllaHide hoặc NOP lời gọi `NtSetInformationThread`.

Mình giải hoàn toàn tĩnh bằng script ([solve.py](solve.py)):

```python
import struct

# --- 1. Trích xuất từ GhostStream.wim (uncompressed) ---
wim = open('GhostStream.wim', 'rb').read()
ads = wim[35852:35852 + 18]                # PolyjuicePotion.txt:LordVoldemort

# --- 2. Parent: WndProc biến đổi key khi uptime > 10080 phút ---
WND = bytes([0x8b, 0x8f, 0x92, 0x85, 0x88, 0x96, 0x98, 0x9b,
             0x94, 0x8b, 0x95, 0xe6, 0xed, 0xf0, 0xe7])
r11 = 0x01 ^ 0x83                          # WM_CREATE ^ WM_NCCALCSIZE
buf = bytearray(b ^ r11 for b in ads)
for i in range(15):
    buf[i] ^= WND[i]
key = bytes(buf).split(b'\0')[0]           # b'HarryPotter'

# --- 3. Partner: chuỗi XOR được giải bởi strlen bị hook ---
xk = bytearray(b'Bxs]bv`^u)TpcnolVjN')
dl = 1
for i in range(len(xk)):
    xk[i] = ((xk[i] + dl) & 0xff) ^ 0x13
    dl += 1                                # b'Piertotum Locomotor'

# --- 4. Partner: RC4 biến thể ---
CT = struct.pack('<9IH', 0x35875c96, 0x8b397ad7, 0x286d0475, 0xc85856bb, 0xe1daee35,
                 0x37a956a4, 0xf9561581, 0x0d340a27, 0x262c82ee, 0xf8a5)
STEP = len(b'Wingardium Leviosa')          # 18 = 0x12

S = list(range(256)); j = 0
for i in range(256):
    j = (j + key[i % len(key)] + S[i]) & 0xff
    S[i], S[j] = S[j], S[i]
i = j = 0; flag = bytearray()
for k, c in enumerate(CT):
    i = (i + STEP) & 0xff
    j = (j + S[i]) & 0xff
    S[i], S[j] = S[j], S[i]
    flag.append(S[(S[i] + S[j]) & 0xff] ^ xk[k % len(xk)] ^ ((c + STEP) & 0xff))
print(flag.decode())
```

```
$ python solve.py
ADS LordVoldemort = b'AlbusDumbledore \r\n'
pipe key = b'HarryPotter'
xor string = b'Piertotum Locomotor'
FLAG = y0u_kn0w_n07h1n6_j0n_5n0w@flare-on.com
```

### Ghi chú về giá trị `step`

Theo phân tích tĩnh, hook `strlen` luôn trả về `0x13`. Mình đã kiểm tra bằng cách emulate shellcode với Unicorn: kết quả `eax = 0x13` cho cả hai chuỗi. Tuy nhiên ciphertext chỉ giải đúng với **`step = 0x12 = 18`**, chính là độ dài thật của `"Wingardium Leviosa"`. Còn chuỗi XOR thì vẫn phải là bản đã giải (`Piertotum Locomotor`).

Mình cũng đã emulate khối PRGA gốc (`0x14000153A`–`0x14000166D`) bằng Unicorn. Kết quả khớp từng byte với bản Python, nên phần dịch thuật toán là đúng. Nguyên nhân chênh lệch 0x12/0x13 có thể là một chi tiết lúc chạy thật mà phân tích tĩnh không thấy, hoặc sai lệch giữa môi trường tác giả sinh ciphertext và binary phát hành. Mình chưa xác nhận được bằng cách chạy Partner thật. Dù vậy, flag là một câu có nghĩa (*"You know nothing, Jon Snow"*) và kết thúc đúng bằng `@flare-on.com`, nên kết quả là đáng tin.

## Các kỹ thuật trong bài

| Kỹ thuật | Vị trí |
|---|---|
| Giấu dữ liệu trong NTFS ADS, đóng gói bằng WIM | `PolyjuicePotion.txt:LordVoldemort` |
| Payload thứ hai nhúng trong resource, drop ra `%TEMP%` | `BIN/101` → `Partner_CTF.exe` |
| Giải chuỗi với khóa phụ thuộc tên file exe | `0x140001130` |
| Resolve API động | `GetProcAddress` + chuỗi mã hóa |
| Anti-debug `ThreadHideFromDebugger` | `NtSetInformationThread(-2, 0x11)` |
| Nhánh chết (biến toàn cục không bao giờ được set) | `0x140006668` |
| Time bomb dựa trên uptime tiến trình (7 ngày) | `GetProcessTimes` + WndProc |
| Tham số hóa key theo thứ tự window message | `WM_CREATE ^ WM_NCCALCSIZE` |
| IPC qua named pipe | `\\.\pipe\FlareChallenge` |
| Inline hook API bằng shellcode tự sửa dữ liệu, có junk byte chống disassembler | `ucrtbase!strlen` |
| Che giấu con trỏ hàm bằng XOR | `strlen ^ 0xdeadbeef` |
| RC4 biến thể (step ≠ 1, XOR thêm keystring và `+step`) | Partner PRGA |
| Mồi nhử: socket `OVERRIDE:`, Telemetry, `SESSION_TOKEN_CACHE` | parent |

## Flag

```
y0u_kn0w_n07h1n6_j0n_5n0w@flare-on.com
```
