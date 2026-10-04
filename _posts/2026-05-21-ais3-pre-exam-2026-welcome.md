---
title: "AIS3 Pre-exam 2026 - Welcome Writeup"
date: "2026-05-21 00:00:00 +0800"
categories: ["CTF Write-ups"]
tags: ["ctf", "ais3-pre-exam-2026", "misc"]
description: "透過 QR Code 與 Qrs App 取得 Welcome 題目的 flag。"
toc: true
source_url: "https://hackmd.io/PI8L2Nk0T_Wl4dCs-mc8NQ"
source_tag: "AIS3_Pre_exam 2026"
---

> 原始筆記：[HackMD](https://hackmd.io/PI8L2Nk0T_Wl4dCs-mc8NQ) · 比賽：AIS3 Pre-exam 2026

{% raw %}
> Category: Misc  

---

## 題目描述：

![image](/assets/img/writeups/H1j39x31Mg.png)

點擊題目描述中的網址：

```text
https://ais32026scanme.pwn2ooown.tech/
```

會得到以下 QR Code 畫面：

![image](/assets/img/writeups/By8Zsg2kzg.png)

透過手機取掃描該 QR Code 後，手機會跳轉到 Qrs 這個 App 的畫面：

![image](/assets/img/writeups/H1BToxh1fx.png)

這時候只要用這個 App 掃描那個 QR code 直到 100% 就會得到一張圖片：

![IMG_2846](/assets/img/writeups/rySiheh1Mg.png)

圖片上就會有此題的 Flag 了。

---

## Flag

```text
AIS3{Hello_LLM_welcome_to_pre_exam_2026!}
```

---
{% endraw %}
