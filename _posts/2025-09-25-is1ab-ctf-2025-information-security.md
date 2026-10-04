---
title: "is1abCTF 2025 - Information Security"
date: "2025-09-25 00:00:00 +0800"
categories: ["CTF Write-ups"]
tags: ["ctf", "is1ab-ctf-2025", "osint"]
description: "根據題目中的社群帳號線索，整理 Information Security 的 OSINT 解題過程。"
toc: true
source_url: "https://hackmd.io/aNs6oSSuQYOGe6NGCkkwoA"
source_tag: "is1abCTF2025-writeup"
---

> 原始筆記：[HackMD](https://hackmd.io/aNs6oSSuQYOGe6NGCkkwoA) · 比賽：is1abCTF 2025

{% raw %}
## 1.思考、嘗試過程

![image](/assets/img/writeups/Bkfe3LRjxe.png)

- 這題根據題目敘述`rokku_888_ 在多個社群平台上皆有活躍紀錄`以及`順利通過了身份驗證流程(使用身分證字號)`，可以知道我們要從社群平台中找`rokku_888_`這個帳號，然後從這個帳號找到洩漏身分證字號的地方。
- 經過一番的尋找，以及根據題目給的.jpg檔，可以在IG中找到對應的帳號內容:

![image](/assets/img/writeups/SJgSRU0ogg.png)

![IMG_2143](/assets/img/writeups/H1Sj080slx.png)

- 接者在從這個IG帳號中，將限動、貼文都翻過一遍後，在此篇貼文找到了關鍵的身分證資訊:

![image](/assets/img/writeups/B1qCMDAixx.jpg)

- 將此張照片用手機增加曝光後，就能夠從身分證號 ID的地方，推測出完整的flag了。

## 2.參考資料
1. IG
{% endraw %}
