# FLARE-On 13 — Challenge 6: Threat Invaders

**Flag:** `wh4t_4_l0ng_str4ng3_tr1p_1ts_b33n@flare-on.com`

> *"…over a hundred megabytes, there are sophisticated score-keeping algorithms that need to communicate
> with our official record keeping servers."*

## Tổng quan

`6-ThreatInvaders.7z` (mật khẩu `flare`) chứa 2 file:

| File | Kích thước | Mô tả |
|---|---|---|
| `ThreatInvaders.exe` | 116.238.508 | Game Space Invaders viết bằng C# (.NET 10, WinForms), publish dạng **single-file self-contained** |
| `challenge.pcapng` | 403.960 | Capture HTTP giữa client và "official record keeping server" |

Challenge **không có server sống** (CTFd không đặt `connection_info`) ⇒ mọi thứ phải giải ra từ 2 file.
Bí mật nằm ở **native host** của file exe, không nằm ở managed code — và flag **không** nằm trong
pcap ở dạng rõ.

## Bản đồ giải quyết

```
ThreatInvaders.exe (native host = CoreCLR tự chế, có JIT hook)
        │
        │  hook GetMachineGuid   → lấy MachineGuid của máy (16 byte) làm KHÓA
        │  hook EncodeFeedbackBuffer → rò rỉ (sessionGUID ⊕ machineGUID) vào telemetry
        │  hook ReplaceHighscores → giải mã comment của entry "cmd:" rồi tách "prog;args"
        │  hook LaunchUpdate     → ghi đè path/argument ⇒ game thực thi lệnh của server
        ▼
challenge.pcapng
        │
        ├─ telemetry #3 : feedback[0:16] = session ⊕ machine  → suy ra MachineGuid
        ├─ entry "BANANA" (cmd 'E') : comment mã hóa → "cmd:cmd.exe;/c dir"
        ├─ entry "BENIGN" (cmd 'C') : comment mã hóa → "cmd:cmd.exe;/c type flag.txt"
        ├─ telemetry #4 : stdout của `dir`          (mã hóa cùng PRNG)
        └─ telemetry #5 : stdout của `type flag.txt` (mã hóa cùng PRNG)  ← FLAG
```

---

## 1. Nhận diện đối tượng

```bash
file ThreatInvaders.exe
# PE32+ executable for MS Windows 6.00 (GUI), x86-64, 9 sections
```

Đây là **.NET single-file**: apphost native + bundle đính kèm. Tự `bundle_list.txt`/script
`tools/netbundle.py` rút ra 254 file:

```bash
python3 tools/netbundle.py ThreatInvaders.exe work/bundle-all
# header at 0x6ed6ecd / ver 6 0 files 254 id gfIAavSV582B
```

Kiểm tra tính toàn vẹn: **251 DLL framework** trong bundle khớp **byte-for-byte** với NuGet
`Microsoft.NETCore.App.Runtime.win-x64 10.0.11` + `Microsoft.WindowsDesktop.App.Runtime.win-x64 10.0.11`
⇒ **không có assembly nào bị sửa**. Chỉ có `ThreatInvaders.dll` là mã của tác giả (100.864 byte).

## 2. Managed code: dọn sạch, và cả một cái bẫy

```bash
~/tools/dntools/ilspycmd -p -o work/decompiled work/bundle-all/ThreatInvaders.dll
```

Ra một game Space Invaders hoàn chỉnh (42 type, 403 method): `GameWorld`, `Renderer`, `SoundBank`,
`HighscoreService`, `HttpRemoteScoreClient`, `TelemetryReporter`, `DebugScoreInjector`…

* **Không có** một lời gọi mã hóa nào (`grep -iE "crypt|sha|md5|hmac|aes|random|base64"` chỉ ra
  `Convert.ToBase64String/FromBase64String`, `Guid.NewGuid`, `GetMachineGuid`).
* Toàn bộ 259 chuỗi `ldstr` đối chiếu với `#US` heap ⇒ không có chuỗi ẩn.
* Sweep cả 116 MB bằng XOR/ADD/SUB/ROT (C, ~9 phút) cho `@flare-on.com`, `flare-on.com`, `flag{` ⇒ không có.

### 2.1. Flag giả (decoy)

Trong `UpdateLauncher` có một chuỗi base64:

```
LS1pbnN0YWxsLWRpciBXb3VsZG4ndF9pdF9iZV9uaWNlX2lmX3RoaXNfd2FzX3RoZV9yZWFsX2ZsYWdAbm8tZmxhcmUuY29tIC0tY3dkIEJ1dF9zYWRseV9pdF9pc24ndA
→ "--install-dir Wouldn't_it_be_nice_if_this_was_the_real_flag@no-flare.com --cwd But_sadly_it_isn't"
```

Domain là `@no-flare.com` chứ không phải `@flare-on.com` ⇒ **mồi nhử**, y như challenge 4.

### 2.2. Ba dấu hiệu "lạ" trong managed code (đều có thật, nhưng không phải nơi giấu flag)

| Dấu hiệu | Giải thích |
|---|---|
| `TelemetryReporter._machineId` được tính (đọc `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`) nhưng **không nơi nào dùng** | Chính **native host** dùng nó (xem mục 4) |
| `Program.Main` cứng `headlessUpdate = true` ⇒ MessageBox "Server note:" chết | Không ảnh hưởng: `LaunchUpdate` vẫn chạy, và bị hook ghi đè |
| `TryFillArgBuffer` **không** giải mã base64 | Vô nghĩa: hook native ghi đè buffer đó |

## 3. Pcap: protocol và những cái bẫy

```bash
tshark -r challenge.pcapng -q -z conv,tcp        # 1 TCP conn, 203 request / 203 response
tshark -r challenge.pcapng -Y http.request.method==POST -T fields -e http.file_data
```

Protocol (client `.NET` ⇄ server):

| Endpoint | Ghi chú |
|---|---|
| `GET /api/v1/health` | `{status, entries, time}` |
| `GET /api/v1/highscores?limit=25` | `{entries[], total}` |
| `GET /api/v1/version` | `{"latest":"1.0.0.1","message":""}` |
| `POST /api/v1/highscores` | upload score (`id, player_name, score, wave_reached, duration_seconds, achieved_at, comment_b64`) |
| `POST /api/v1/telemetry` | `{request_id, session_id, games_played, client_version, feedback_b64, feedback_length}` |

Đều kèm header `X-Api-Key: ed347a07305214ab98974a008674eb78cd03b1fedb73c8be9f79e40fb8e155b0`.

**Bẫy 1 – đừng tìm flag trong pcap.** Payload telemetry và comment của các record `cmd:` đều là
**ngẫu nhiên thật** (entropy 7.62/8 bit cho 530 byte; χ² ≈ số bậc tự do). `flare-on`/`@flare-on.com`
**không xuất hiện** một lần nào trong pcap.

**Bẫy 2 – pcap là *synthetic*.** SYN quảng bá MSS 1460 nhưng có frame mang payload 1791–4096 byte ⇒
không thể do TCP stack thật sinh ra. Pcap là bản mô phỏng lại protocol để làm *spec* cho người chơi.

**Bẫy 3 – `feedback_length` là bitfield, không phải độ dài.**
`8208 = 16|0x2000`, `16914 = 530|0x4000`, `16430 = 46|0x4000`. Ở client .NET gốc,
`BuildDocument` gán `feedback_length = min(len, 4096)` ⇒ **client trong exe không giải thích được pcap** ⇒
phải tìm phần "còn lại" của client.

### 3.1. Channel ngầm: bảng điểm có "lệnh"

Hai record do server chèn vào (mỗi record chỉ xuất hiện ở **một** lần poll rồi biến mất):

```json
{"player_name":"BANANA","score":2066361377,"wave_reached":69,"duration_seconds":0,
 "comment_b64":"+bmPsSZwC3eIRD/rvqXFfnzf"}
{"player_name":"BENIGN","score":1932142625,"wave_reached":67,"duration_seconds":0,
 "comment_b64":"GenjMZg28ziV/EU2YTRDGmZISVPsEraqrCO03g=="}
```

Cả hai đều thỏa mãn:

```python
score.to_bytes(4,'little') XOR player_name[:4] == b"cmd:"     # 0x21 0x2c 0x2a 0x7b / 0x21 0x28 0x2a 0x73
```

`wave_reached` = 69 = `'E'` và 67 = `'C'` ⇒ **mã lệnh**. Còn `comment_b64` là **ciphertext**.

## 4. Native host: CoreCLR tự chế có JIT-hook

Đây là mấu chốt. `singlefilehost` chính thức của Microsoft có 9.987.072 byte và in
`App host version: 10.0.11`; file của ta có 10.063.104 byte và in:

```
App host version: 10.0.4-dev          ← bản build tự chế
```

Bên trong nó có **hook tầng JIT**: khi JIT sắp biên dịch một method, nó so tên method với các
**hash 64-bit** rồi cài handler riêng. (Tên method không nằm trong file ⇒ phải **đảo ngược hash**.)

```python
def name_hash(name):
    b = name.encode()
    seed = ((b[0] ^ 0x8f3a2c91d7b4e6a5) * 0xc53a1b7f2d9e4467) & M
    h, m = seed, 0x5ca6e801706eaaac
    for c in b[1:]:
        if c == 0: break
        h = ((c ^ h) * m) & M; m = (m * 0x2545f4914f6cdd1d + 1) & M
    return h
```

| hash | method được hook | rva handler |
|---|---|---|
| `0x322131f288b022a7` | `ReplaceHighscores` | `0xc66f0` |
| `0x6f8ff9636eae6c5a` | `LaunchUpdate` | `0xc6a70` |
| `0x3f926793476b8710` | `GetMachineGuid` | `0xf54e0` |
| `0xa3a845aec791499a` | `GetSessionID` | `0xc6df0` |
| `0x6397c52d5293345e` | `EncodeFeedbackBuffer` | `0xc6ba0` |

### 4.1. Handler `ReplaceHighscores` (rva `0xc66f0`)

Quét mảng `HighscoreStruct[]` (80 byte/record: `Score@+0x3c`, `PlayerName@+0x28`,
`Comment(ptr)@+0x50`, `CommentLength@+0x58`, `FormatVersion@+0x3a == 3`) và với record mà
`hash(Score XOR PlayerName[0..3]) == 0xce723a0a685e63e4` (marker `"cmd:"`) thì **giải mã `Comment`**,
rồi copy sang 2 buffer, **tách tại dấu `;`**:

```
0x7FF600 : phần 1 (program)      0x7FF820 : phần 2 (arguments)
```

### 4.2. Handler `LaunchUpdate` (rva `0xc6a70`)

```asm
mov  r8, [0x7ff5f0]                ; len phần 1
lea  rdx, [0x7ff600]
add  rcx, 0x10                     ; pathBuffer + 16
call memcpy
mov  r8, [0x7ff810]                ; len phần 2
lea  rcx, [rdi+0x10]               ; argument + 16
lea  rdx, [0x7ff820]
call memcpy
```

⇒ `UpdateLauncher.LaunchUpdate` bị ghi đè: game **thực sự chạy** `program arguments` do server gửi.

### 4.3. Handler `GetMachineGuid` / `EncodeFeedbackBuffer` — đường rò khóa

* `GetMachineGuid` (rva `0xf54e0`): copy 16 byte MachineGuid từ registry vào global `0x7FFA30`.
* `EncodeFeedbackBuffer` (rva `0xc6ba0`): ghi **16 byte `sessionGUID ⊕ machineGUID`** vào feedback buffer
  ⇒ **pcap rò rỉ khóa giải mã**.

### 4.4. Thuật toán giải mã (rva `0xc65e0`)

```asm
; seed = xxh64_avalanche(A ^ ((A>>2) + 0x9e3779b97f4a7c15 + (A<<6) + B))
;   A = machineGUID[0:8], B = machineGUID[8:16]
; vòng lặp:
;   st = st*0x5851f42d4c957f2d + 0x14057b7ef767814f
;   out[i] ^= (byte)(st >> 56)
```

**Quan trọng:** `st` là **global**. Decryptor kiểm tra `if (st == 0) seed;` ⇒ **mọi lần giải mã trong
cùng phiên dùng chung một dòng keystream**, nên vị trí offset là quan trọng.

## 5. Lấy khóa từ pcap

Telemetry #3 có feedback 16 byte đầu = `session ⊕ machine`:

```python
leak    = bytes.fromhex("54ae032ea875b0f8cc578a511fe71631")   # feedback[0:16] của telemetry #3
session = net_guid_bytes("478b635d-c335-4c12-b1de-16e0565be335")[::-1]
machine = bytes(a ^ b for a, b in zip(leak, session))
# -> 614d587848636e4980454964586c756c
# -> MachineGuid = 78584d61-6348-496e-4549-64586c756c
```

## 6. Giải mã hai lệnh của server

```python
ks = keystream(machine, ...)          # state toàn cục, nối tiếp nhau
dec(banana, machine, 0)      # 'E' được giải mã trước  -> b"cmd:cmd.exe;/c dir"
dec(benign, machine, 548)    # 'C' giải mã sau, offset 548 -> b"cmd:cmd.exe;/c type flag.txt"
```

Vậy server bảo client:

* chạy `cmd.exe /c dir` → liệt kê thư mục
* chạy `cmd.exe /c type flag.txt` → **in nội dung file flag**

## 7. Đọc flag: telemetry #4 và #5 chính là stdout

Hai telemetry cuối chứa **output của hai lệnh trên**, mã hóa bằng **cùng PRNG**:

```python
dec(fb_672, machine,  18)   # telemetry #4 (530 byte) -> output của `dir`
dec(fb_821, machine, 576)   # telemetry #5 ( 46 byte) -> output của `type flag.txt`
```

Output của `dir` — tự xác nhận cơ chế:

```
 Directory of Z:\CTFs\FlareOn\SpaceInvaders\space-invaders\src\SpaceInvaders\bin\Release\net10.0-windows\publish\win-x64

15/09/2026  19:22    <DIR>          .
23/08/2026  10:30    <DIR>          ..
15/09/2026  19:34               324 config.json
30/08/2026  23:23                46 flag.txt          ← đúng 46 byte = payload telemetry #5
15/09/2026  17:29       116.238.508 ThreatInvaders.exe
```

Output của `type flag.txt`:

```
wh4t_4_l0ng_str4ng3_tr1p_1ts_b33n@flare-on.com
```

## 8. Marker thứ hai: `"fun!"`

Trong handler còn một nhánh nữa: `hash(comment[0..4]) == 0x5045a536b62b2c6`, và hash đó ứng với chuỗi
**`"fun!"`** (tìm ra bằng brute-force 95⁴). Đó chính là comment của entry **BOOM** mà server tự chèn
(`"fun!"`), dùng để bật cờ "reward" khi client đã rò đủ khóa (đòi hỏi cả `[0x7fd61e]` và `[0x7fd5ff]`).
Server trả `reward_now: true` cho telemetry #5 — đúng telemetry mang nội dung flag.

## 9. Kết quả & kiểm chứng

```text
FLAG: wh4t_4_l0ng_str4ng3_tr1p_1ts_b33n@flare-on.com
```

* Độ dài 46 byte — khớp đúng kích thước `flag.txt` trong output `dir`.
* Submit lên CTFd (FLARE-ON 13): `{"success": true, "data": {"status": "correct"}}` ✔

Script tái lập độc lập (chỉ cần 2 file gốc):
[`6/solve_threatinvaders.py`](solve_threatinvaders.py)

```bash
python3 6/solve_threatinvaders.py
```

## 10. Bài học

1. **Đừng tin managed code là toàn bộ.** `singlefilehost` chính thức có 9.987.072 byte và ghi
   `App host version: 10.0.11`; bản của challenge là build **CoreCLR tự chế** (`10.0.4-dev`) — dấu hiệu
   nhỏ nhất cũng đáng soi (size lệch, `App host version` lệch).
2. **Hook ở tầng JIT là kỹ thuật hay**: mã độc không cần nằm trong assembly, chỉ cần *nhận diện* tên
   method lúc biên dịch. Vì vậy phải **đảo ngược hash tên method** thay vì tìm chuỗi.
3. **PRNG state toàn cục ⇒ phải theo dõi thứ tự.** Cùng một thuật toán, cùng một khóa, nhưng offset
   keystream khác nhau thì ra rác — đây là lý do `cmd 'C'` không giải mã được ở offset 0.
4. **Pcap là spec, không phải bằng chứng.** Nó chứa dữ liệu *đã mã hóa*; flag chỉ lộ ra sau khi bạn
   tái tạo đúng client (ở đây là client có hook native).
5. **Dùng "nguồn" của dữ liệu.** `dir` output trong telemetry cho thấy `flag.txt` 46 byte — kiểm chứng
   độc lập rằng payload telemetry #5 chính là flag.
