---
title: "is1abCTF 2025 - Baby Reverse"
date: "2025-09-22 00:00:00 +0800"
categories: ["Reverse Engineering", "CTF Write-ups"]
tags: ["ctf", "is1ab-ctf-2025", "reverse-engineering"]
description: "分析四個資料轉換函式，使用 Python 逆推 Baby Reverse 的輸入。"
toc: true
source_url: "https://hackmd.io/Nt3c7cYFS_uJQELWBKxeUw"
source_tag: "is1abCTF2025-writeup"
---

> 原始筆記：[HackMD](https://hackmd.io/Nt3c7cYFS_uJQELWBKxeUw) · 比賽：is1abCTF 2025

{% raw %}
## 思考、嘗試過程

![image](/assets/img/writeups/HytIrw0oex.png)

- 這題將.zip壓縮檔解壓縮，會獲得一個.exe檔:

![image](/assets/img/writeups/S13qHPCsll.png)

- 我首先將它丟給 DIE 進行分析，檢查它有沒有被加殼:

![image](/assets/img/writeups/BJRbLw0sxl.png)

- 可以從圖片中發現它沒有被加殼。
- 那麼接下來就可以直接將它丟到 IDA 中進行分析:
    ![image](/assets/img/writeups/BJ0tLw0jll.png)
- 可以從圖片中看到，這題只是一個簡單的輸入驗證執行檔而已，只是它經過了 4 個加密函式，因此往這4個加密函式去分析:
- 首先去看 crypt_func1()經過反編譯後的結果:

![image](/assets/img/writeups/ByB8vwAjxe.png)

- 可以清楚的看出，它只是將使用者輸入的值，一個一個和0x11做 XOR 運算後，放到v2這個陣列中，然後回傳。
- 接者往 crypt_func2()分析:

![image](/assets/img/writeups/rJzwqDCjee.png)

- 從圖片中，可以看到此函式根據 crypt_func1()回傳的值，將此值依據奇數/偶數來決定要 +38 還是 -17，然後再更新到 v3 這個陣列中，for迴圈結束後，回傳 v3 這個陣列。
- 接者在往 crypt_func3()分析

![image](/assets/img/writeups/HkBkpvRogl.png)

- 當 i 不等於3的倍數時，會先判斷i是否為奇數，若是則a1[i] - 9，否則a1[i] ^ 0x4D 
- 當 i 等於3的倍數時根據 a1[i] 的值 +5，放到 v2[i] 中。
- 接者分析 crypt_func4()

![image](/assets/img/writeups/rJ6o1d0jlx.png)

![image](/assets/img/writeups/HkJpydRslg.png)

- 可以從圖片發現，這個函式只是做位移運算而已。
- 接者去看Check函式

![image](/assets/img/writeups/ryHIZdRsgl.png)

- 得知這題只要使用者輸入的內容跟 Str 這個變數一致就會輸出Correct!!!
- 因此我們只要寫程式去回推 Str 這個變數即可知道使用者要輸入什麼，而使用者輸入的內容則為flag。
## 解密腳本

```python
def rol1(b): return ((b << 1) & 0xFF) | (b >> 7)

# 將 check() 內的 64-bit 常數以小端序串成 bytes（含結尾 0x00，strlen 會在 0x00 前停止）
import struct
qwords = [
    0x3A9C9AACCD21BF36,
    0xC90DC22EE285A60A,
    0xE2A4A68D9FAB9C27,
    0xB50BEA04D18EB534,
    0xBC2ECB8CEA1A51AE,
    0x0000294D2C4B35E9A4
]
data = b"".join(struct.pack("<Q", q) for q in qwords)
x4 = data[:data.find(b"\x00")]  # strlen(Str)

# 反向 crypt_func4
x3 = bytes(rol1(b) for b in x4)

# 反向 crypt_func3
tmp = bytearray(len(x3))
for i, b in enumerate(x3):
    if i % 3 == 0:
        tmp[i] = (b - 5) & 0xFF
    elif i % 3 == 1:
        tmp[i] = (b + 9) & 0xFF
    else:
        tmp[i] = b ^ 0x4D
x2 = bytes(tmp)

# 反向 crypt_func2
tmp = bytearray(len(x2))
for i, b in enumerate(x2):
    if i % 2 == 0:  # even
        tmp[i] = (b + 17) & 0xFF
    else:           # odd
        tmp[i] = (b - 38) & 0xFF
x1 = bytes(tmp)

# 反向 crypt_func1
userinput = bytes(b ^ 0x11 for b in x1)
print(userinput.decode("latin1"))

```
{% endraw %}
