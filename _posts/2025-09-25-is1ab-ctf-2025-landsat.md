---
title: "is1abCTF 2025 - 哪傻X出這啥題阿"
date: "2025-09-25 00:00:00 +0800"
categories: ["CTF Write-ups"]
tags: ["ctf", "is1ab-ctf-2025", "osint"]
description: "利用 Landsat 座標與衛星影像字母，還原題目要求的 flag。"
toc: true
source_url: "https://hackmd.io/XSi2SjfDSDeDGfcGZt8hSw"
source_tag: "is1abCTF2025-writeup"
---

> 原始筆記：[HackMD](https://hackmd.io/XSi2SjfDSDeDGfcGZt8hSw) · 比賽：is1abCTF 2025

{% raw %}
## 1.思考、嘗試過程

![image](/assets/img/writeups/ByYSFU0jxe.png)

![image](/assets/img/writeups/HyIJ9ICogl.png)

- 這題根據題目的描述，以及題目提供的.txt檔中的內容，可以推測是要用座標去猜測圖片中形狀代表什麼字母，然後來組成 flag。
- 因此我先將隨便一個座標丟到Google中，進行搜尋，結果找到了這個網站:

![image](/assets/img/writeups/SyexoIRsll.png)

- 從這個網站中，針對.txt檔中的每個座標進行一個一個搜尋，就可以組成完整的flag了。

## 2.參考資源
[Your Name in Landsat Interactive](https://landsat.gsfc.nasa.gov/your-name-in-landsat-interactive/)
{% endraw %}
