# FLARE-On 13 — Challenge 1: FLAreCAPTCHA

**Flag:** `triskaidekaphobia@flare-on.com`

## Tổng quan

Archive `1-flarecaptcha.7z` (mật khẩu `flare`) chứa đúng một file: `flarecaptcha.html`, một trang giả lập widget reCAPTCHA v2 "I'm not a robot". Toàn bộ logic nằm trong đoạn `<script>` cuối file, nên có thể giải hoàn toàn bằng phân tích tĩnh.

```
$ python -c "import py7zr; py7zr.SevenZipFile('1-flarecaptcha.7z', password='flare').extractall('1')"
$ ls 1
flarecaptcha.html
```

## Phân tích

### 1. Cái bẫy chuột trái

Handler `mousedown` có hai nhánh:

```js
if (e.button === (Math.pow(5, 0) + Math.pow(1, 1))) {   // 1 + 1 = 2  -> chuột PHẢI
    ... // nhánh sinh flag
}
else if (e.button === 0) {                               // chuột trái
    ... // quay spinner 1s rồi triggerFailure()
}
```

Click trái như người bình thường thì luôn nhận dấu X đỏ và thông báo *"Robot, or unskilled reverse engineer detected."*. Nhánh đúng là `e.button === 2`, tức **chuột phải**. Context menu đã bị chặn bằng `preventDefault()`.

Sau khi bấm chuột phải, một `setTimeout(..., 2000)` được khởi động. Nếu nhả chuột phải (`mouseup` với `button === 2`) hoặc rời chuột khỏi ô (`mouseleave`) trước khi hết 2 giây, `cancelHold()` sẽ gọi `triggerFailure()`. Vì vậy phải **giữ chuột phải ít nhất 2 giây**.

### 2. Dữ liệu flag và Proxy

```js
const recaptchaLogoBitmap = [123, 5, 102, 4, 100, 22, 102, 19, 106, 28, 110, 7, 103, 24,
                             109, 30, 110, 55, 105, 27, 110, 5, 106, 90, 96, 25, 33, 20, 96, 26];

const recaptchaLogoBitmapProx = new Proxy(recaptchaLogoBitmap, {
    get(target, prop) {
        if (typeof prop === 'string' && !isNaN(prop)) {
            const envShift = document.characterSet.length;
            return target[prop] ^ envShift;
        }
        return target[prop];
    }
});
```

Mọi truy cập theo chỉ số đều bị XOR với `document.characterSet.length`. Trang khai báo `<meta charset="UTF-8">`, nên `"UTF-8".length = 5`.

> Nếu lưu/mở file với một encoding khác (ví dụ `windows-1252`, độ dài 12), flag sẽ sai. Đây là một chi tiết "phụ thuộc môi trường" có chủ đích.

### 3. Sinh khóa XOR

Trong callback sau 2 giây:

```js
const displayPaddingPx   = Math.round((errorLogTime - errorLogStartTime) / 1000);   // = 2
const widgetLength       = resetWidget.toString().length;                           // = 222
const widgetUpperBoundsPx = (displayPaddingPx * (widgetLength + 1115)) & 0xFFFF;
const wupperLeft  = (widgetUpperBoundsPx >> 8) & 0xFF;
const wupperRight =  widgetUpperBoundsPx       & 0xFF;

const displaySurfaceMap = recaptchaLogoBitmapProx
    .map((b, i) => String.fromCharCode(b ^ (i % 2 === 0 ? wupperLeft : wupperRight)))
    .join('');
```

Các giá trị cần xác định:

| Biến | Giá trị | Ghi chú |
|---|---|---|
| `displayPaddingPx` | `2` | timer 2000 ms, làm tròn theo giây |
| `widgetLength` | `222` | độ dài source của arrow function `resetWidget`, tính chính xác cả whitespace/indent trong file |
| `widgetUpperBoundsPx` | `2 * (222 + 1115) = 2674 = 0x0A72` | |
| `wupperLeft` | `0x0A` | khóa cho chỉ số chẵn |
| `wupperRight` | `0x72` | khóa cho chỉ số lẻ |

`Function.prototype.toString()` trả về nguyên văn source, nên `widgetLength` phụ thuộc vào cách định dạng trong file. Nếu có ai "làm đẹp" hoặc minify lại file HTML thì khóa sẽ sai. Đây là một kỹ thuật chống chỉnh sửa (anti-tamper) nhẹ.

Cuối cùng, mỗi byte bị XOR hai lớp: `b ^ 5 ^ (0x0A | 0x72)`, xen kẽ theo chẵn/lẻ.

## Script giải

```python
import re

bitmap = [123, 5, 102, 4, 100, 22, 102, 19, 106, 28, 110, 7, 103, 24, 109, 30,
          110, 55, 105, 27, 110, 5, 106, 90, 96, 25, 33, 20, 96, 26]

src = open('flarecaptcha.html', encoding='utf-8').read()
reset_src = re.search(r'const resetWidget = (\(\) => \{.*?\n        \});', src, re.S).group(1)
widget_len = len(reset_src)                      # 222

env_shift = len('UTF-8')                         # document.characterSet.length = 5
seconds = 2                                      # thời gian giữ chuột phải

w = (seconds * (widget_len + 1115)) & 0xFFFF
left, right = (w >> 8) & 0xFF, w & 0xFF

flag = ''.join(chr((b ^ env_shift) ^ (left if i % 2 == 0 else right))
               for i, b in enumerate(bitmap))
print(flag)   # triskaidekaphobia@flare-on.com
```

### Kiểm chứng bằng known-plaintext

Mọi flag FLARE-On đều kết thúc bằng `@flare-on.com`. XOR 13 byte cuối của bitmap (đã XOR 5) với chuỗi này sẽ khôi phục được hai khóa độc lập mà không cần biết `widgetLength`, và kết quả khớp với `0x0A`/`0x72`. Thử với 1 giây hoặc 3 giây thì chỉ ra ký tự rác, nên 2 giây là giá trị duy nhất đúng.

## Cách giải "như con người"

Mở `flarecaptcha.html` trong trình duyệt, **giữ chuột phải** trên ô checkbox khoảng 2 giây rồi nhả. Trang sẽ hiện dấu tick xanh kèm flag.

## Flag

```
triskaidekaphobia@flare-on.com
```

*Triskaidekaphobia* nghĩa là chứng sợ số 13, đúng với FLARE-On **13**.
