---
title: "is1abCTF 2025 - Tree Verification"
date: "2025-09-24 00:00:00 +0800"
categories: ["Reverse Engineering", "CTF Write-ups"]
tags: ["ctf", "is1ab-ctf-2025", "reverse-engineering"]
description: "動態分析自製殼與 .is1ab section，追蹤 Tree Verification 的驗證流程。"
toc: true
source_url: "https://hackmd.io/rgEia8kEQq6-kji4HzfIlg"
source_tag: "is1abCTF2025-writeup"
---

> 原始筆記：[HackMD](https://hackmd.io/rgEia8kEQq6-kji4HzfIlg) · 比賽：is1abCTF 2025

{% raw %}
## 思考、嘗試過程

![image](/assets/img/writeups/rJamIzehee.png)

- 這題我將執行檔，直接丟到 DIE 中，進行分析。

![image](/assets/img/writeups/rkUhLZ-2gg.png)

- 從 Entropy 中，可以發現此執行檔有一個 section 被加殼了。從題目描述中，可以知道這個殼是一個獨特的殼。
- 接者我將此執行檔丟到 IDA Pro 中進行動態分析，因為它是一個被加殼過的執行檔。所以需要用動態分析，才能夠了解加殼前的原始內容。

![image](/assets/img/writeups/HJny1G-nge.png)

- 從圖片中可以看到，它一開始呼叫 GetModuleHandleA(0) 將 chal.exe 執行檔載入到記憶體中。
- 然後經過一連串的運算，進入到 .is1ab section 中，接者往下一個區塊分析。

![image](/assets/img/writeups/Hy_rWGbngx.png)

- 這個區塊會計算目前的 index 是否超過 .is1ab section 的大小
- 接者往左下區塊分析:

![image](/assets/img/writeups/SkewWG-2lx.png)

- 從圖片中可以知道這個區塊做的事情，只是單純的使用 byte_572000 這個陣列中的值，和 `.is1ab section` 中的一個 bytes 的值做 XOR，然後將 XOR 的結果和 index 相減。
- 因此我們可以猜測 byte_572000 是一個 key 的陣列。
- 知道這些後，我們就可以將 `.is1ab section` 中的內容 dump 出來，然後循環使用 key 陣列中的值進行解殼，還原出原始的 `.is1ab section` 中的內容。
- 解殼腳本:

```python
from pathlib import Path

# 循環使用的 XOR 金鑰
hex_list = [
    0x64, 0x4c, 0x6b, 0x70, 0x74, 0x6e, 0x32, 0x7d, 0x24, 0x62, 0x6a,
    0x56, 0x4e, 0x36, 0x6b, 0x29, 0x77, 0x7b, 0x27, 0x47, 0x52, 0x58,
    0x35, 0x38, 0x75, 0x28, 0x50, 0x40, 0x36, 0x31, 0x7a, 0x68
]
key = bytes(hex_list)

IN_FILE   = "dumpfile"            # 原始 dump

# 解殼：plain[i] = (cipher[i] ^ key[i % klen]) - i (mod 256)
ct = Path(IN_FILE).read_bytes()
pt = bytearray(len(ct))
klen = len(key)
for i, b in enumerate(ct):
    x = b ^ key[i % klen]
    pt[i] = (x - i) & 0xFF

with open("tree.exe", "wb") as f:
    f.write(pt)
```

- 然後將解殼完後的內容，重新寫成一個.exe 的執行檔，再對它進行逆向分析。
- 將 tree.exe 丟到 IDA 中之後，我直接先去看有沒有特別的字串存在。

![image](/assets/img/writeups/Ski8XBbhle.png)

- 從圖片中可以看到 `Verification succeeded!` 和 `Verification failed!` 的關鍵字，因此往這兩個字串所在的函式進行分析。

![image](/assets/img/writeups/H1bKVHW3ge.png)

- 可以從圖片中看到此 sub_40200C 函式就是那兩個字串所在的地方，因此可以猜測這個函式中，呼叫的其他函式有可能藏著 flag 驗證的行為，或產生 flag 的行為。
- 因此依序分析 sub_402130()、sub_401440()和 sub_401A06()這幾個函式。

![image](/assets/img/writeups/Sy9qSS-hle.png)

- sub_402130 這個函式從反編譯後的結果看不出來，它的具體行為是在做什麼，因此先往下繼續分析。

![image](/assets/img/writeups/SkZeIH-2xg.png)

- sub_401440 這個函式看起來也不是很重要的一個函式。因此繼續往下分析。

![image](/assets/img/writeups/Bk0surWheg.png)

![image](/assets/img/writeups/Skya_rZ3xx.png)

- 從圖片中可以看到 sub_401A06() 這個函式呼叫了多次的 sub_40194E()，並且帶入的第一個參數都是一個字元，且有幾行呼叫 sub_40194E() 函式時，帶入的第二個參數是上一行 sub_40194E() 回傳值，因此可以猜測 sub_40194E() 可能跟建構 flag 有關係。

![image](/assets/img/writeups/Bkd-qrb3lx.png)

- 從圖片中可以看到 `is1abCTF` 的關鍵字，因此上述的猜測是合理的，既然我們已經抓到關鍵的函式了。我們就可以請 GPT 幫我們還原出原始的 flag 資訊。
- 以下是請 GPT 寫的 Python 腳本:

```python
class Node:
    def __init__(self, ch, left=None, right=None):
        # ch can be int (ASCII code) or single-character string
        self.ch = chr(ch) if isinstance(ch, int) else ch
        self.left = left
        self.right = right

def postorder(n: Node) -> str:
    if n is None:
        return ""
    return postorder(n.left) + postorder(n.right) + n.ch

def build_tree() -> Node:
    # Mirror the exact construction in sub_401A06
    v33 = Node('R', None, None)
    v32 = Node('A', v33, None)
    v31 = Node('v', v32, None)
    v30 = Node(116, None, None)      # 't'
    v29 = Node(51, v30, v31)         # '3'
    v28 = Node(82, v29, None)        # 'R'
    v27 = Node(95, None, None)       # '_'
    v26 = Node(36, v27, v28)         # '$'
    v25 = Node(83, None, None)       # 'S'
    v24 = Node(49, None, None)       # '1'
    v23 = Node(95, v24, v25)         # '_'
    v22 = Node(49, None, None)       # '1'
    v21 = Node(95, v22, None)        # '_'
    v20 = Node(36, v21, v23)         # '$'
    v19 = Node(48, v20, None)        # '0'
    v18 = Node(95, None, None)       # '_'
    v17 = Node(70, v18, None)        # 'F'
    v16 = Node(85, v19, v17)         # 'U'
    v15 = Node(84, None, None)       # 'T'
    v14 = Node(70, v15, None)        # 'F'
    v13 = Node(123, v14, None)       # '{'
    v12 = Node(110, None, v16)       # 'n'
    v11 = Node(55, None, v13)        # '7'
    v10 = Node(114, None, v11)       # 'r'
    v9  = Node(49, None, None)       # '1'
    v8  = Node(115, None, None)      # 's'
    v7  = Node(97, v8, v9)           # 'a'
    v6  = Node(105, None, None)      # 'i'
    v5  = Node(98, v6, v7)           # 'b'
    v4  = Node(67, None, v5)         # 'C'
    v3  = Node(51, v10, None)        # '3'
    v2  = Node(69, v4, v3)           # 'E'
    v1  = Node(97, v2, v26)          # 'a'
    root = Node(125, v1, v12)        # '}'
    return root

if __name__ == "__main__":
    root = build_tree()
    flag = postorder(root)
    print(flag)

```

- 執行完後的結果:

![image](/assets/img/writeups/Sy_Dsrbnxl.png)
{% endraw %}
