---
title: "is1abCTF 2025 - Image Encryptor"
date: "2025-09-23 00:00:00 +0800"
categories: ["Reverse Engineering", "CTF Write-ups"]
tags: ["ctf", "is1ab-ctf-2025", "reverse-engineering"]
description: "解開 UPX 殼並分析圖片加密流程，使用 Python 還原圖片。"
toc: true
source_url: "https://hackmd.io/_287FFbiQ52Ygjtz0Aclig"
source_tag: "is1abCTF2025-writeup"
---

> 原始筆記：[HackMD](https://hackmd.io/_287FFbiQ52Ygjtz0Aclig) · 比賽：is1abCTF 2025

{% raw %}
## 思考、嘗試過程

![image](/assets/img/writeups/HknmHWx3ll.png)

- 這題將壓縮檔解壓縮後，會獲得一個 .exe 執行檔和加密過的 .jpg 檔

![image](/assets/img/writeups/ByIWLbe3xx.png)

- 因此可以猜測這題是要我們解密這個 .jpg 檔，然後取得圖片中的 flag。
- 知道這些資訊後，我們就可以將 .exe 檔先丟給 DIE 進行分析，檢查有沒有被加殼。

![image](/assets/img/writeups/SyaOvbl3gx.png)

- 從圖片中，可以看到它被UPX加殼，因此可以使用 UPX 這個工具，對它進行解殼。

![image](/assets/img/writeups/SytfuZxhxg.png)

- 解完殼後，就可以將它丟給 IDA 進行分析。
- 進入到 IDA 後，我習慣去看有沒有一些關鍵的字串，可以先從這個字串所在的函式進行分析。

![image](/assets/img/writeups/HJXiq-lnxe.png)

- 可以從圖片中看到 `encrypted_image.jpg`，因此跳去這個字串所在的函式位置。

![image](/assets/img/writeups/rJnk3-ehxx.png)

- 從圖片中可以看到，這個函式開啟了 image.jpg 檔，然後再加密過後的 .jpg 檔中，寫入 `is1abCTF` 這幾個關鍵字。
- 接者繼續往下分析

![image](/assets/img/writeups/rJQi0Wehee.png)

- 從圖片中看到出現了一個 while 迴圈，然後呼叫了 sub_140001473()、sub_140001910()和 sub_140001491()，因此可以猜測這個區塊對 image.jpg 做了一些處理。
- 因此先往 sub_140001473() 這個函式分析

![image](/assets/img/writeups/HkvfxMg2lx.png)

- 可以看到它將 dword_140008030 *= 16870 然後回傳它，至於 dword_140008030 的初始值為多少我們不知道。
- 接者在往 sub_140001910(v7, v6)函式分析，它帶入的兩個參數，分別為 fgetc() 取出來的1個bytes，以及 sub_140001473 函式的回傳值。

![image](/assets/img/writeups/HkS6-fe2xg.png)

- 可以看到它回傳了一個函數指標，帶入的參數為(v7, v6)，這邊比較特別的是，這個函數指標是一個陣列的形式，意思是它會根據 [v6 & 0x1F] 的值，從 funcs_140001954 中選一個函式出來使用。

![image](/assets/img/writeups/HJVdQfxnle.png)

- 而 0x1F 這個值，它剛好是十進制的32，因此可以猜測 funcs_140001954 陣列中，總共有32個函式可以使用。
- 我們先往 sub_140001517 這個函式去查看。

![image](/assets/img/writeups/ByvbNfehxl.png)

- 可以看到它只是做簡單的 XOR 運算。
- 由於funcs_140001954函式數量有32個，因此這邊就只顯示其中一個函式的內容。
- 接者回到 sub_140001491() 進行分析

![image](/assets/img/writeups/HkivEfg2ge.png)

- 可以看到這個函式只是做一些邏輯、位移的運算。
- 當我們將這三個函式內容都分析完後，其實就可以將 sub_14000195D 和 while 迴圈中使用到的三個函式都丟給GPT，然後請它幫我們寫一個解密的 Python腳本，就可以取得原始的圖片。

```python
from pathlib import Path

MAGIC = b"Is1abCTF"
SEED  = 303739666

def rol8(x, r):
    r &= 7
    return ((x << r) | (x >> (8 - r))) & 0xFF

def ror8(x, r):
    r &= 7
    return ((x >> r) | ((x << (8 - r)) & 0xFF)) & 0xFF

class LCG16807_32:
    def __init__(self, seed):
        self.state = seed & 0xFFFFFFFF
    def next(self):
        self.state = (self.state * 16807) & 0xFFFFFFFF
        return self.state

INV5  = 205  # 5*205 ≡ 1 (mod 256)
INV3  = 171  # 3*171 ≡ 1 (mod 256)
INV11 = 163  # 11*163 ≡ 1 (mod 256)

# --- inverses for funcs[0..31] in 原始順序 ---
def inv_00(y,k): return y ^ k                          # a2 ^ a1
def inv_01(y,k): return (y - k) & 0xFF                 # a1 + k
def inv_02(y,k): return (y + k) & 0xFF                 # a1 - k
def inv_03(y,k): return (~y) & 0xFF                    # ~a1
def inv_04(y,k): return rol8(y, k & 7)                 # ROR(a1, k&7)
def inv_05(y,k): return ror8(y, k & 7)                 # ROL(a1, k&7)
def inv_06(y,k): return ((y << 4) | (y >> 4)) & 0xFF   # swap nibbles
def inv_07(y,k): return y ^ (k >> 4)                   # a1 ^ (k>>4)
def inv_08(y,k): return y ^ (k & 0x0F)                 # (k&0xF) ^ a1
def inv_09(y,k): return (k ^ (~y & 0xFF)) & 0xFF       # ~(k ^ a1)
def inv_10(y,k): return y ^ 0x55                       # a1 ^ 0x55
def inv_11(y,k): return y ^ 0xAA                       # a1 ^ 0xAA
def inv_12(y,k): return (y - (k >> 4)) & 0xFF          # (k>>4) + a1
def inv_13(y,k): return (y + (k & 0x0F)) & 0xFF        # a1 - (k&0xF)
def inv_14(y,k): return ((~y & 0xFF) - k) & 0xFF       # ~(a1 + k)
def inv_15(y,k): return (k - y) & 0xFF                 # k - a1

def inv_16(y,k):
    h = (y >> 4) & 0x0F
    l = (y & 0x0F) ^ h
    return ((h << 4) | l) & 0xFF                       # a1 ^ (a1>>4)

def inv_17(y,k):
    # y = (a1<<4) ^ a1 => y_hi = l ^ h, y_lo = l
    l = y & 0x0F
    h = ((y >> 4) & 0x0F) ^ l
    return ((h << 4) | l) & 0xFF

def inv_18(y,k): return rol8(y,1)                      # ROR(a1,1)
def inv_19(y,k): return ror8(y,1)                      # ROL(a1,1)
def inv_20(y,k): return rol8(y,2)                      # ROR(a1,2)
def inv_21(y,k): return ror8(y,2)                      # ROL(a1,2)
def inv_22(y,k): return rol8(y,3)                      # ROR(a1,3)
def inv_23(y,k): return ror8(y,3)                      # ROL(a1,3)
def inv_24(y,k): return y ^ ror8(k,4)                  # a1 ^ ROR(k,4)
def inv_25(y,k): return (y - rol8(k,4)) & 0xFF         # a1 + ROL(k,4)
def inv_26(y,k): return (y - k - 1) & 0xFF             # a1 + k + 1
def inv_27(y,k): return ((y - k) * INV5) & 0xFF        # 5*a1 + k
def inv_28(y,k): return ((y - k) * INV3) & 0xFF        # 3*a1 + k   
def inv_29(y,k): return ((y - k) * INV11) & 0xFF       # 11*a1 + k  
def inv_30(y,k): return y                               # identity
def inv_31(y,k): return (y - 1) & 0xFF                  # a1 + 1

INV_FUNCS = [
    inv_00, inv_01, inv_02, inv_03, inv_04, inv_05, inv_06, inv_07,
    inv_08, inv_09, inv_10, inv_11, inv_12, inv_13, inv_14, inv_15,
    inv_16, inv_17, inv_18, inv_19, inv_20, inv_21, inv_22, inv_23,
    inv_24, inv_25, inv_26, inv_27, inv_28, inv_29, inv_30, inv_31
]

def decrypt_file(enc_path="encrypted_image.jpg", out_path="image.jpg"):
    data = Path(enc_path).read_bytes()
    if not data.startswith(MAGIC):
        raise ValueError("Magic header not found; wrong file?")
    c = data[len(MAGIC):]

    prng = LCG16807_32(SEED)
    out = bytearray()
    i = 0
    n = len(c)

    while i < n:
        r0 = prng.next(); s0 = (r0 >> 8) & 7; k0 = r0 & 0xFF; idx0 = (r0 >> 16) & 0x1F
        if i + 1 < n:
            r1 = prng.next(); s1 = (r1 >> 8) & 7; k1 = r1 & 0xFF; idx1 = (r1 >> 16) & 0x1F
            c2 = c[i]; c1 = c[i+1]; i += 2
            t2 = rol8(c2, s1); p1 = INV_FUNCS[idx1](t2, k1) & 0xFF
            t1 = rol8(c1, s0); p0 = INV_FUNCS[idx0](t1, k0) & 0xFF
            out.append(p0); out.append(p1)
        else:
            c1 = c[i]; i += 1
            t1 = rol8(c1, s0); p0 = INV_FUNCS[idx0](t1, k0) & 0xFF
            out.append(p0)

    Path(out_path).write_bytes(out)
    
    print(f"Decryption complete → {out_path} ({len(out)} bytes)")

if __name__ == "__main__":
    decrypt_file()
```

- 執行完這個腳本後，就可以獲得 image.jpg 檔，將其點開後，即可獲得此題的 flag。

![image](/assets/img/writeups/ryQaHMe2eg.png)
{% endraw %}
