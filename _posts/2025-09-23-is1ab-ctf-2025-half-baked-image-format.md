---
title: "is1abCTF 2025 - Half-Baked Image Format"
date: "2025-09-23 00:00:00 +0800"
categories: ["CTF Write-ups"]
tags: ["ctf", "is1ab-ctf-2025", "misc"]
description: "分析 MUZI 圖片格式與轉換程式，還原 flag 圖片。"
toc: true
source_url: "https://hackmd.io/G9gksWCsR02KaNmdM5fuZg"
source_tag: "is1abCTF2025-writeup"
---

> 原始筆記：[HackMD](https://hackmd.io/G9gksWCsR02KaNmdM5fuZg) · 比賽：is1abCTF 2025

{% raw %}
## 思考、嘗試過程

![image](/assets/img/writeups/BJm0TYynle.png)

- 將題目給的壓縮檔下載下來後，在資料夾中發現一個 .py 檔和一個 flag.muzi 的檔案。

![image](/assets/img/writeups/HJecE5J2xx.png)

- 因此我先去看 .py 檔中程式碼內容:

```python
from PIL import Image
import numpy as np
import crc8

def main():
    inp = input("""
                Welcome to the is1ab Image Program
                It can convert images to MUZIs
                It will also display MUZIs

                [1] Convert Image to MUZI
                [2] Display MUZI

                """)
    match inp:
        case "1":
            start_conv()
        #case "2":
            #display() #TODO: Add
            '''
            ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
            ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣀⣀⣀⣀⣀⣀⣀⣀⣀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
            ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣀⡀⠂⠁⠁⠁⠁⠂⠂⠂⠂⠁⠁⠁⠁⠁⠁⠂⠄⡀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
            ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣀⠂⠁⠁⠂⡀⣀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣀⡀⠄⠂⠁ ⠁⠂⡀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
            ⣿⣿⣿⣿⣿⣿⣀⡀⠁⠂⡀⣀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣀⠄⠁  ⠁⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
            ⣿⣿⣿⣿⣿⡀⠁⠂⣀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⡀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
            ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣀⡀⠄⠄⠄⠄⠄⠄⠄⠄⡀⡀⣀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
            ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⠂⠂⠄⠄⠄⡀⡀⠄⠄⠄⠄⠂⠂⠁⠁⠁⠂⠄⣀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
            ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠄⠄⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⠄⠂⠁⠁⠄⣀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
            ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣀⠄ ⠁⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
            ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
            ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⠂⠂⠂⠂⠂⠂⠂⠄⡀⣀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
            ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⠁⠂⡀⡀⡀⡀⡀⡀⠄⠄⠁  ⠂⣀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
            ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠄⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⠁ ⠄⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
            ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
            ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
            ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⠁⠄⡀⣀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
            ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣀⠄⠂⠁⠁⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
            ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
            ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
            '''
        case _:
            return 0
    return 0

def start_conv():
    file = input("Enter the path to your image you want converted to a MUZI file:\n")
    out = input("Enter the path you’d like to write the MUZI to:\n")
    img = Image.open(file)
    w, h = img.size

    write = [
        b'\x4D', b'\x55', b'\x5A', b'\x49', b'\x00', b'\x01', b'\x00', b'\x02'
    ]

    for x in w.to_bytes(4):
        write.append(x.to_bytes(1))
    for y in h.to_bytes(4):
        write.append(y.to_bytes(1))

    write.append(b'\x57')
    write.append(b'\x49')
    write.append(b'\x46')
    write.append(b'\x49')
    
    for i in range(h):
        dat = [b'\x44',b'\x41',b'\x54',b'\x52']
        for j in range(w):
            dat.append(img.getpixel((j,i))[0].to_bytes(1)) 
        dat.append(getCheck(dat[4:]))
        for wa in dat:
            write.append(wa)

    for i in range(h): 
        dat = [b'\x44',b'\x41',b'\x54',b'\x47']
        for j in range(w):
            dat.append(img.getpixel((j,i))[1].to_bytes(1)) 
        dat.append(getCheck(dat[4:]))
        for wa in dat:
            write.append(wa)

    for i in range(h): 
        dat = [b'\x44',b'\x41',b'\x54',b'\x42']
        for j in range(w):
            dat.append(img.getpixel((j,i))[2].to_bytes(1))
        dat.append(getCheck(dat[4:]))
        for wa in dat:
            write.append(wa)

    write.append(b'\x44')
    write.append(b'\x41')
    write.append(b'\x54')
    write.append(b'\x45')

    with open(out, "ab") as f:
        for b in write:
            f.write(b)

    return 0

def getCheck(datr):
    dat = ''
    for w in datr:
        dat+=chr(int.from_bytes(w))
    #print(datr)
    #print(dat.encode())
    return int.to_bytes(int(crc8.crc8(dat.encode()).hexdigest(),base=16),1)

if __name__ == '__main__':
    main()
```

- 從程式碼可以大致知道運作流程，它要求使用者輸入一個 image，然後會將 write 陣列中的 byte值，寫到這個 image 中，最後產生一個 .muzi 檔。
- 現在題目給了我們一個 flag.muzi 檔，那麼我們只要寫一個Python腳本，將這個 flag.muzi 檔，還原成 .png 檔，就可以讀取圖片中的 flag。
- 還原的腳本我直接請GPT幫忙產生，如下所示:

```python
from PIL import Image
import numpy as np
import crc8
import os

MAGIC = b"MUZI"           # 0x4D 55 5A 49
VER   = b"\x00\x01\x00\x02"
WIFI  = b"WIFI"           # 0x57 49 46 49
TAG_R = b"DATR"           # per-row + R channel
TAG_G = b"DATG"           # per-row + G channel
TAG_B = b"DATB"           # per-row + B channel
END   = b"DATE"           # file end

def main():
    inp = input(
        "Welcome to the is1ab Image Program\n"
        "It can convert images to MUZIs\n"
        "It will also display MUZIs\n\n"
        "[1] Convert Image to MUZI\n"
        "[2] Display MUZI\n\n"
    ).strip()

    if inp == "1":
        start_conv()
    elif inp == "2":
        display()
    else:
        print("Bye.")

def start_conv():
    file = input("Enter the path to your image you want converted to a MUZI file:\n").strip()
    out  = input("Enter the path you’d like to write the MUZI to:\n").strip()

    img = Image.open(file).convert("RGB")
    w, h = img.size
    pix = img.load()

    write = bytearray()
    write += MAGIC
    write += VER

    # 寬高用 big-endian 寫 4 bytes（統一規格）
    write += int(w).to_bytes(4, "big")
    write += int(h).to_bytes(4, "big")

    write += WIFI

    # 逐列寫入：R rows → G rows → B rows（每列有 1-byte CRC）
    # 計算 CRC 的方法與原碼一致：對該列的原始 bytes 做 crc8
    def row_crc(row_bytes: bytes) -> int:
        # 與原碼等效：原碼把每個 byte 轉 chr 再 encode，實際等於對 row_bytes 本身做 CRC
        c = crc8.crc8()
        c.update(row_bytes)
        return int(c.hexdigest(), 16) & 0xFF

    # R channel
    for i in range(h):
        row = bytes(pix[j, i][0] for j in range(w))
        write += TAG_R
        write += row
        write += row_crc(row).to_bytes(1, "big")

    # G channel
    for i in range(h):
        row = bytes(pix[j, i][1] for j in range(w))
        write += TAG_G
        write += row
        write += row_crc(row).to_bytes(1, "big")

    # B channel
    for i in range(h):
        row = bytes(pix[j, i][2] for j in range(w))
        write += TAG_B
        write += row
        write += row_crc(row).to_bytes(1, "big")

    write += END

    # 用 'wb'（覆寫），避免多次執行造成檔尾重複
    with open(out, "wb") as f:
        f.write(write)

    print(f"Done. Wrote MUZI to: {out}")

def display():
    muzi_path = input("Enter the path to the MUZI file you want to display/restore:\n").strip()
    out_path  = input("Enter the path to save the restored image (e.g., output.png):\n").strip()

    with open(muzi_path, "rb") as f:
        data = f.read()

    idx = 0
    def take(n: int) -> bytes:
        nonlocal idx
        if idx + n > len(data):
            raise ValueError("Unexpected end of file while parsing.")
        b = data[idx:idx+n]
        idx += n
        return b

    # 1) header
    if take(4) != MAGIC:
        raise ValueError("Bad MAGIC (not MUZI).")
    if take(4) != VER:
        raise ValueError("Version mismatch.")

    # 2) width/height（我們解讀為 big-endian；如果你一開始用其他版本寫出的檔案是 little-endian，可在這裡切換）
    w = int.from_bytes(take(4), "big")
    h = int.from_bytes(take(4), "big")

    if w <= 0 or h <= 0 or w > 20000 or h > 20000:
        raise ValueError(f"Unreasonable dimensions parsed: {w}x{h}")

    if take(4) != WIFI:
        raise ValueError("Missing WIFI tag after header.")

    r = np.zeros((h, w), dtype=np.uint8)
    g = np.zeros((h, w), dtype=np.uint8)
    b = np.zeros((h, w), dtype=np.uint8)

    def expect_rows(tag: bytes, target: np.ndarray, label: str):
        def crc_utf8_like_original(row: bytes) -> int:
            # 完全模擬原 getCheck：把每個 byte 變 chr 再用 UTF-8 encode
            s = ''.join(chr(b) for b in row)
            c = crc8.crc8()
            c.update(s.encode())  # 預設 UTF-8
            return int(c.hexdigest(), 16) & 0xFF

        def crc_raw_bytes(row: bytes) -> int:
            c = crc8.crc8()
            c.update(row)
            return int(c.hexdigest(), 16) & 0xFF

        for i in range(h):
            t = take(4)
            if t != tag:
                raise ValueError(f"Row {i}: expected {tag!r}, got {t!r} for {label}.")

            row = take(w)      
            crc_file = take(1)[0]

            # 先試「原版 UTF-8」演算法；不行再試「raw bytes」
            calc_utf8 = crc_utf8_like_original(row)
            if crc_file != calc_utf8:
                calc_raw = crc_raw_bytes(row)
                if crc_file != calc_raw:
                    raise ValueError(
                        f"Row {i} {label}: CRC mismatch. expected {crc_file:#04x}, "
                        f"got utf8 {calc_utf8:#04x} / raw {calc_raw:#04x}"
                    )
            # 寫入像素
            target[i, :] = np.frombuffer(row, dtype=np.uint8)

    # 3) 依序讀 R, G, B 區段
    expect_rows(TAG_R, r, "R")
    expect_rows(TAG_G, g, "G")
    expect_rows(TAG_B, b, "B")

    # 4) 結尾
    tail = take(4)
    if tail != END:
        raise ValueError(f"Missing END tag 'DATE'. Got {tail!r}")

    # 5) 組合與輸出
    rgb = np.dstack([r, g, b])
    img = Image.fromarray(rgb, mode="RGB")

    os.makedirs(os.path.dirname(os.path.abspath(out_path)) or ".", exist_ok=True)
    img.save(out_path)
    print(f"Restored image saved to: {out_path}")

if __name__ == '__main__':
    main()
```

- 執行完後的結果:

![image](/assets/img/writeups/BybAXik2gg.png)

- 查看 flag.png 中的內容:

![image](/assets/img/writeups/H1eWNiJnlx.png)
{% endraw %}
