---
title: "is1abCTF 2025 - I love free music"
date: "2025-09-22 00:00:00 +0800"
categories: ["CTF Write-ups"]
tags: ["ctf", "is1ab-ctf-2025", "osint"]
description: "從圖片與社群貼文確認人物姓名，透過 MD5 完成解題。"
toc: true
source_url: "https://hackmd.io/ewstaXHDRFWJKWzv8szOOg"
source_tag: "is1abCTF2025-writeup"
---

> 原始筆記：[HackMD](https://hackmd.io/ewstaXHDRFWJKWzv8szOOg) · 比賽：is1abCTF 2025

{% raw %}
## 思考、嘗試過程

![image](/assets/img/writeups/rJWTULColl.png)

- 這題將圖片下載下來，將圖片點開後:

![image](/assets/img/writeups/BkZHPIAilx.png)

- 可以從圖片中，看到織府這兩個關鍵字，因此上網搜尋織府音樂祭
- 從搜尋中找到一篇FB貼文:

![image](/assets/img/writeups/HJ73DI0ole.png)

- 裡面有這場音樂祭演出的團體名稱，然後根據題目描述知道，只需要將中文丟到 MD5 進行雜湊

![image](/assets/img/writeups/ryHrd8Aslg.png)

- 經過測試發現這題的 flag 是 "宋德鶴" 這個名字，將他經過 MD5 雜湊後，即可獲得正確的 flag。
{% endraw %}
