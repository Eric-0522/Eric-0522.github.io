---
title: "is1abCTF 2025 - 這裡有人壞壞"
date: "2025-09-22 00:00:00 +0800"
categories: ["CTF Write-ups"]
tags: ["ctf", "is1ab-ctf-2025", "forensics"]
description: "分析 Windows API 紀錄與 net.exe 建立帳號的行為，對照 MITRE ATT&CK 技術。"
toc: true
source_url: "https://hackmd.io/gschFcErQT6tMtuMJRjKaQ"
source_tag: "is1abCTF2025-writeup"
---

> 原始筆記：[HackMD](https://hackmd.io/gschFcErQT6tMtuMJRjKaQ) · 比賽：is1abCTF 2025

{% raw %}
## 1.思考、嘗試過程

![image](/assets/img/writeups/BkVveLAsxx.png)

- 這題題目提供了一個 .7z 壓縮檔，將其解壓縮後，發現裡面有一個30幾萬筆資料 csv 檔案:

![image](/assets/img/writeups/SJuCeU0sll.png)

![image](/assets/img/writeups/rywb-L0jee.png)

- 因此我的第一個想法是將 csv 檔丟給 GPT，並且問它說
     > Windows 中新增使用者帳號，呼叫到的 Windows API是什麼嗎?
- 經過它的分析後，得知這題新增使用者的步驟是:
     > Create Process(net.exe) -> Start Process
- 然後使用 net.exe 這個執行檔來新增使用者 admin，密碼為 Nimda@CYAdmin
    ![image](/assets/img/writeups/rJxjoNUAixl.png)
- 知道密碼為多少後，只需要去查詢 MITRE ATT&CK 中，對應上述的技術是哪個編號，就可以得到這題的flag了。
- 此題的flag:
     > is1abCTF{Nimda@CYAdmin_T1136.001}

## 2.參考資料
[MITRE ATT&CK](https://attack.mitre.org/techniques/T1136/001/)
{% endraw %}
