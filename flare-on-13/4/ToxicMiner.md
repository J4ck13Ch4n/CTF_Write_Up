# FLARE-On 13 — Challenge 4: ToxicMiner

**Flag:** `cpu_m3lt3d_4nd_all_i_g0t_w4s_th1s_fl4g@flare-on.com`

> *"...Dissect the binary before you bake alive, or at least generate enough hash rate to pay off the electricity bill for your captivity."*

## Tổng quan

`4-ToxicMiner.7z` (mật khẩu `flare`) chứa `ToxicMiner.exe`, một PE32+ x64 nặng 4.8 MB. Đây là bản build của **cpuminer-multi 1.3.7** (tpruvot) được link tĩnh với libcurl, OpenSSL và pthreads-win32, nên phần lớn code là thư viện. Việc cần làm là tìm đoạn code tác giả đã cài thêm vào.

Hai chỗ trông khả nghi lúc đầu hoá ra đều là code thư viện bình thường:

* `.ctors` trỏ tới `0x1401b2d90`: đây là hàm init của pthreads-win32 (`QUSEREX.DLL`, `QueueUserAPCEx`).
* `MessageBoxA` nằm trong `OPENSSL_showfatal`.

## 1. Chuỗi mồi nhử

Trong `main` (`0x140100290`), giá trị mặc định của `rpc_user` bị gán thành:

```
bTFuM195MHVyXzB3bl9idXMxbjNzcw==@flare.com   -> base64: "m1n3_y0ur_0wn_bus1n3ss"
```

Chuỗi này có dáng một flag, nhưng domain là `@flare.com` chứ không phải `@flare-on.com`. Đây là mồi nhử.

## 2. Hàm scanhash bị cài cắm (`0x140134f70`)

Import `GetVolumeInformationA` dẫn thẳng tới một hàm scanhash "lạ" được gọi từ miner thread (`0x1401016dd`):

```c
if (!inited) { GetVolumeInformationA(NULL, NULL, 0, &g_serial, 0, 0, 0, 0); inited = 1; }

have_target = 0;
if (rpc_user && strlen(rpc_user) == 64) {          // -u <64 hex>
    for (i = 0; i < 32; i++) sscanf(rpc_user + 2*i, "%02x", &target[i]);
    have_target = 1;
}
do {
    nonce++;
    h = dSHA(g_serial, nonce);                     // 2 lần sha256_transform (đã bị sửa)
    if (have_target && memcmp(h, target, 32) == 0) {
        key = dSHA(g_serial, 0x0B501E7E);          // 0x140134ca0
        rc4(key, 16, enc_flag /*0x1401bd3b0*/, 0x33, out);   // 0x140134d70
        applog(LOG_INFO, "Accepted: %s", out);
        exit(0);
    }
} while (nonce < max_nonce && !work_restart);
```

`dSHA(a, b)` dựng một block SHA-256 gồm hai word `a`, `b`, word padding `0x80000000` và độ dài `0x40` bit, nén một lần, rồi nén thêm lần nữa trên 32 byte kết quả (độ dài `0x100` bit). Nói cách khác, đây là "double SHA-256" kiểu Bitcoin trên 8 byte `serial || nonce`.

Điều quan trọng là **khoá RC4 chỉ phụ thuộc vào volume serial number** của ổ đĩa (32-bit). Nonce và target chỉ là cổng chặn. Vì vậy chỉ cần vét cạn 2^32 giá trị serial, hay đúng như đề nói: *"generate enough hash rate"*.

## 3. SHA-256 đã bị sửa

Tôi thử cài lại bằng `hashlib`, nhưng kết quả không khớp với emulator (Unicorn chạy `0x140134ca0`). `sha256_transform` tại `0x140135240` đã bị chỉnh ở nhiều chỗ. Ví dụ, cuối hàm có thêm một bước trộn:

```c
r = state[0];
state[0] = K_bytes[r & 0xff] ^ *(uint32_t*)((uint8_t*)state + state[1] % 28) ^ r;
```

(`K_bytes` là bảng hằng K của SHA-256 được đọc theo từng byte.) Phần thân vòng lặp cũng khác bản chuẩn.

Viết lại cho khớp từng bit rất tốn công, nên tôi dùng cách khác: **chạy thẳng code gốc**.

## 4. Brute-force bằng code gốc của binary

Các hàm `0x140134ca0` / `0x140135240` là code thuần. Chúng chỉ dùng stack, bảng hằng và security cookie, không gọi API Windows nào. Do đó có thể:

1. Dump image đã map của PE (`pefile.get_memory_mapped_image`) ra `img.bin`.
2. Trong WSL (Linux), `mmap(MAP_FIXED)` một vùng RWX đúng tại `0x140000000` và nạp image vào.
3. Gọi `0x140134ca0` qua con trỏ hàm có `__attribute__((ms_abi))` (calling convention Windows x64: `rcx, rdx, r8`).

Tôi kiểm chứng trước bằng cách so output với Unicorn: cả hai cho cùng `d5335733c3c6...` với serial `0x12345678`.

```c
typedef void (__attribute__((ms_abi)) *kfn)(uint32_t, uint32_t, uint8_t*);
F = (kfn)0x140134ca0;  CT = (uint8_t*)0x1401bd3b0;
for (s = id; s <= 0xffffffff; s += NT) {
    F(s, 0x0B501E7E, h);
    rc4(h, 16, CT, pt, 0x33);
    if (all_printable(pt, 0x33)) printf("serial=%08x flag=%s\n", s, pt);
}
```

Chạy 20 luồng thì chưa tới một phút đã có kết quả (full source: `4/brute.c`):

```
serial=01cec01d flag=cpu_m3lt3d_4nd_all_i_g0t_w4s_th1s_fl4g@flare-on.com
```

Volume serial `01CE-C01D` (đọc là "ICE COLD") là một cái kết hợp với bối cảnh "CPU nóng chảy" của đề.

## Flag

```
cpu_m3lt3d_4nd_all_i_g0t_w4s_th1s_fl4g@flare-on.com
```
