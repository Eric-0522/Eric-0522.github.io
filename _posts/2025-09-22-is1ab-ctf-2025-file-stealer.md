---
title: "is1abCTF 2025 - file_stealer"
date: "2025-09-22 00:00:00 +0800"
categories: ["CTF Write-ups"]
tags: ["ctf", "is1ab-ctf-2025", "forensics"]
description: "使用 7-Zip 檢視磁碟映像與 FAT 檔案，找出 file_stealer 的 flag。"
toc: true
source_url: "https://hackmd.io/a2VqWk9hRJ2Mb9Fq1mWefg"
source_tag: "is1abCTF2025-writeup"
---

> 原始筆記：[HackMD](https://hackmd.io/a2VqWk9hRJ2Mb9Fq1mWefg) · 比賽：is1abCTF 2025

{% raw %}
## 思考、嘗試過程

![image](/assets/img/writeups/B1UraSAsee.png)

- 這題將題目給的zip檔解壓縮後，可以從資料夾中發現一個.img檔

![image](/assets/img/writeups/SJbaaSColx.png)

- 因此我第一個想法是要怎麼讀取.img file?
- 透過上網搜尋後，發現可以使用`7-Zip File Manager`這個工具來讀取。
- 因此我將 .img 檔丟到`7-Zip File Manager`這個工具中

![image](/assets/img/writeups/HywK1LCile.png)

- 可以看到有3個檔案，然後我依序將前兩個檔案點開，在 1.fat 這個檔案中就看到此題的 flag 了

![image](/assets/img/writeups/HJCUyURjlg.png)

![image](/assets/img/writeups/HylexLCilx.png)
{% endraw %}
