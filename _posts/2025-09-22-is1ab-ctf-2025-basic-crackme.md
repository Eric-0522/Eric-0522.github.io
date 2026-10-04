---
title: "is1abCTF 2025 - Basic Crackme"
date: "2025-09-22 00:00:00 +0800"
categories: ["Reverse Engineering", "CTF Write-ups"]
tags: ["ctf", "is1ab-ctf-2025", "reverse-engineering"]
description: "分析 key 的長度檢查、轉換與驗證函式，還原 Basic Crackme 的答案。"
toc: true
source_url: "https://hackmd.io/dLtOIEs7RKmnbZI9NBRINQ"
source_tag: "is1abCTF2025-writeup"
---

> 原始筆記：[HackMD](https://hackmd.io/dLtOIEs7RKmnbZI9NBRINQ) · 比賽：is1abCTF 2025

{% raw %}
## 1.思考、嘗試過程

![image](/assets/img/writeups/HJ5z-pCigl.png)

- 這題根據題目描述，可以知道執行檔沒有加殼、混淆和反debug的技術，因此我就不將它丟到DIE中進行分析了。
- 直接將它丟給 IDA 進行逆向分析。

## 2.分析過程

![image](/assets/img/writeups/B1U9G6Cjxe.png)

- 從圖片中，可以看到一些關鍵字，它要求使用者要輸入一把 key，然後會驗證使用者輸入的 key。
- 因此我猜測驗證 key 的函式為 sub_1400013A0，當這個函式的回傳值不為0時，就會往左邊的區塊走，然後輸出正確的 flag。
- 因此往 sub_1400013A0 這個函式進行分析:

![image](/assets/img/writeups/r1U5NaCogg.png)

- 可以看到第12行的地方，先檢查使用者輸入的長度是否不等於37，若是則回傳0。
- 接者第15行將使用者輸入的內容，複製到 Destination 這個變數中。
- 在第21~24行都有呼叫了 sub_140001240 這個函式，因此我們先看這個函式中的內容:
    ![image](/assets/img/writeups/H1NmLaAieg.png)
- 可以看到這個函式，它根據a1的值，進行& 0xF或者 >> 4的運算後，當作v2陣列的index，再取出對應的值，並進行對應圖片中的運算後，進行回傳。
- 接者在第26行的地方，呼叫了 sub_1400012E0 這個函式，並根據其回傳值是否不為0，若是則回傳1

![image](/assets/img/writeups/rJEtPT0ieg.png)

- 可以從圖片中得知，這個函式每次會從 a1 這個陣列中，一次取4個 bytes 的值和 v3 陣列作比較，若不相等則回傳0
- 將有用到的function都分析完後，為了節省時間直接請GPT幫我們寫一個腳本，還原出正確的輸入內容。

```python
#!/usr/bin/env python3

# ---- invert the nibble S-box used in sub_140001240 ----
def sub_1240_inv(y: int) -> int:
    M = [0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15]
    Minv = [0]*16
    for i,v in enumerate(M):
        Minv[v]=i
    lo = y & 0xF
    hi = (y >> 4) & 0xF
    return (Minv[lo] << 4) | Minv[hi]

# ---- unpack 10 DWORD blocks back to Destination[40] ----
def unpack_blocks_to_destination(blocks_unsigned):
    D = [0]*40
    for j in range(10):
        v = blocks_unsigned[j] & 0xFFFFFFFF
        # Block[j] = (sub(D[4j+1])<<24) | (sub(D[4j+3])<<16) | (sub(D[4j+2])<<8) | sub(D[4j+0])
        b0 =  v        & 0xFF
        b2 = (v >> 8)  & 0xFF
        b3 = (v >> 16) & 0xFF
        b1 = (v >> 24) & 0xFF
        D[4*j+0] = sub_1240_inv(b0)
        D[4*j+1] = sub_1240_inv(b1)
        D[4*j+2] = sub_1240_inv(b2)
        D[4*j+3] = sub_1240_inv(b3)
    return D

# ---- simulate sub_140001000 to print the flag from userinput ----
def sub_140001000_sim(userinput_bytes):
    v6 = [64,1,86,74,39,16,6,5,1,102,87,21,60,14,8,22,61,79,20,17,103,5]
    v7 = [ord('8'), ord('b'), ord('a'), ord('W'), 127,37,37,114,26,85,60,28,11,18,41]
    v = v6 + v7                      # total 37 bytes
    t = [(userinput_bytes[i] ^ v[i]) & 0xFF for i in range(37)]
    out = bytearray(37)
    for i,b in enumerate(t):
        # mirror the exact C logic order
        if not (65 <= b <= 90):
            if 97 <= b <= 122:
                out[i] = ((b - 84) % 26) + 97
            else:
                out[i] = b
        else:
            out[i] = ((b - 52) % 26) + 65
    return bytes(out)

def main():
    # signed constants from sub_1400012E0
    v3_signed = [
        -433789332, 40534546, 1815012958, -695967214, 1819172522,
        -1396925846, -429986636, -324766550, -1031501274, -1061109718
    ]
    blocks_unsigned = [x & 0xFFFFFFFF for x in v3_signed]

    D = unpack_blocks_to_destination(blocks_unsigned)

    userinput = bytes(D[:37])
    print("userinput:", userinput.decode('latin1'))

    flag = sub_140001000_sim(userinput)
    print("flag:", flag.decode('latin1'))

if __name__ == "__main__":
    main()

```

- 經過執行後，即可得到正確的flag。

![image](/assets/img/writeups/r1ZL2aAogg.png)
{% endraw %}
