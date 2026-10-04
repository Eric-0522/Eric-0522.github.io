---
title: "is1abCTF 2025 - Crypto Party"
date: "2025-09-22 00:00:00 +0800"
categories: ["CTF Write-ups"]
tags: ["ctf", "is1ab-ctf-2025", "crypto"]
description: "逆推 Base64、Rail Fence、Vigenère 與 Affine 等編碼和加密步驟。"
toc: true
source_url: "https://hackmd.io/lP8A-Qi9SWCN2H4XMb3HGw"
source_tag: "is1abCTF2025-writeup"
---

> 原始筆記：[HackMD](https://hackmd.io/lP8A-Qi9SWCN2H4XMb3HGw) · 比賽：is1abCTF 2025

{% raw %}
## 1.思考、嘗試過程
- 這題根據題目的敘述，可以知道密文經過6種不同的加密或編碼。

![image](/assets/img/writeups/r13_5mRslx.png)

- 因此只要從第六步往回推，就可以還原出正確的flag。
    > 將字串反轉 -> Base64 -> Rail Fence Cipher -> Caesar -> Vigenere -> Affine Cipher

- 將字串反轉，並且經過 Base64 解碼後，得到以下結果:

![image](/assets/img/writeups/B1qcpm0jxe.png)

- 接者對解碼後的結果，進行柵欄加密演算法的解密，經過測試獲得一串看起來很像flag的字串:
    > co1mfGPH{qOxggEu_pS_vJa_GbKtps_TMnVy}

- 為什麼這邊說看起來很像，是因為 GbKtps_TMnVy 這串看起來很像 Crypto Party
- 還有前面的prefix co1mfGPH 可以猜測它對應上 is1abCTF 這幾個關鍵字

- 由於我們已經大致猜測出 flag 整體的 Patten 了。因此針對 Caesar 解密，我們可以假設它的shift 為0。意思是將柵欄加密演算法解密後的結果，直接丟到 Vigenère 加密演算法進行解密。

- 剩下的兩種加密方式，我直接請GPT進行分析，經過它的分析後，可以得知 Vigenère 加密使用的金鑰為 KEY，而仿射加密的 key 為(7,14)可以獲得此題正確的 flag。

    > is1abCTF{wElcoMe_tO_tHe_CrYpto_PArTy}

## 2.參考資源
[Vigenère cipher](https://hackmd.io/@okii77/HkCojTDRp)
[仿射密碼](https://zh.wikipedia.org/zh-tw/%E4%BB%BF%E5%B0%84%E5%AF%86%E7%A2%BC)
{% endraw %}
