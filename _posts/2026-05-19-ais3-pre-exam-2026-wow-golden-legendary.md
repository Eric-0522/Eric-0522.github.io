---
title: "AIS3 Pre-exam 2026 Writeup - wow-golden-legendary"
date: "2026-05-19 00:00:00 +0800"
categories: ["Reverse Engineering", "CTF Write-ups"]
tags: ["ctf", "ais3-pre-exam-2026", "reverse-engineering"]
description: "分析 Unity Mono 遊戲與抽卡 API，理解客戶端 rate 參數的信任問題。"
toc: true
source_url: "https://hackmd.io/o-_6sCL3TWm3c78f9b1njw"
source_tag: "AIS3_Pre_exam 2026"
---

> 原始筆記：[HackMD](https://hackmd.io/o-_6sCL3TWm3c78f9b1njw) · 比賽：AIS3 Pre-exam 2026

{% raw %}
## 題目資訊

- 題型：Reverse
- 平台：Windows / Unity Mono
- 主要檔案：`Reverse1.exe`、`Reverse1_Data/Managed/Assembly-CSharp.dll`

## 題目概述

這題給的是一個 Unity 遊戲發行目錄，表面上看起來像是「打怪 + 商店 + 抽卡」的小遊戲。  
直覺上這種題目很容易讓人先去找資源檔或 UI 文字，但實際上真正的關鍵在 `Assembly-CSharp.dll` 的遊戲邏輯。

這題的核心漏洞是：

- 客戶端會把一個名為 `rate` 的數值直接送到遠端 gacha API。
- 正常遊戲流程下，`rate` 只會落在 `0.0 ~ 0.3`。
- 伺服器卻信任這個 client-side `rate`。
- 只要自己重送 request，把 `rate` 改成大於 `0.3`，伺服器就會把 flag 放進回傳 JSON 裡。

## 分析環境

- IDA Pro + IDA Pro MCP
- PowerShell / curl
- 選擇直接分析 `Assembly-CSharp.dll`

## 一、初步觀察

看到目錄結構後，可以先判斷這是標準的 Unity Mono 遊戲：

```text
Reverse1.exe
Reverse1_Data/
  Managed/
    Assembly-CSharp.dll
    UnityEngine*.dll
```


對 Unity 題來說，優先目標通常是：

1. `Assembly-CSharp.dll`
2. `globalgamemanagers`
3. `StreamingAssets`

這題裡最值得看的是 `Assembly-CSharp.dll`，因為符號幾乎沒有被去掉，類別名稱非常清楚，像是：

- `GameManager`
- `GachaServer`
- `GachaUI`
- `GachaStation`
- `ShopUI`
- `PlayerStats`

看到這些名字後，基本上就可以直接鎖定抽卡系統。

## 二、找到遠端 API

先看 `GameManager::.ctor`，可以直接看到預設值：

```csharp
PlayerName = "Anonymous";
GachaServerUrl = "http://chals1.ais3.org:50001";
```


也就是說，抽卡不是純本地邏輯，而是會打遠端 API。

接著看 `GachaServer::Roll`：

```csharp
var url = GameManager.Instance?.GachaServerUrl ?? "";
if (string.IsNullOrWhiteSpace(url))
{
    LocalFallback(spend, onDone);
    return;
}
StartCoroutine(RollCoroutine(url, spend, onDone));
```


這段告訴我們兩件事：

- 平常會走遠端 API。
- 只有 URL 空掉或請求失敗時才會走 `LocalFallback()`。

所以真正的解題點很可能在 server 端邏輯，而不是本地抽卡池。

## 三、還原抽卡 request 格式

重點在 `GachaServer::<RollCoroutine>d__7::MoveNext`。

這裡可以看到它組了一個 JSON POST body，內容包含：

```json
{
  "spend": ...,
  "rate": ...,
  "username": ...,
  "gold": ...,
  "score": ...,
  "kills": ...
}
```


其中最關鍵的是 `rate`。

程式碼前半段先做：

```csharp
rate = UnityEngine.Random.Range(0.0f, 0.3f);
```


然後把這個 `rate` 原封不動塞進 POST body 裡送到 server。

也就是說：

- 正常情況下，client 只會送出 `0.0 <= rate < 0.3`
- 但 server 是否真的驗證這件事，還不知道

這就是非常典型的 client-side trust 問題。

## 四、確認遊戲正常流程

為了避免只是在猜，我又往前追 `GachaUI::ConfirmAmount`：

```csharp
amount = Int32.Parse(_inputStr);
if (amount < 50) ...
if (amount > currentGold) ...
GameManager.SpendGold(amount);
StartCoroutine(RollCoroutine(amount));
```


可以確認：

- 玩家輸入金額後，遊戲會先扣錢
- 然後才去打 gacha API

也就是說，client 傳出去的 `gold` 是扣款後的值。  
不過後來實測發現，解題關鍵其實不是 `gold`，而是 `rate`。

## 五、實際對 API 做黑箱測試

先送一筆正常長相的 request：

```http
POST / HTTP/1.1
Host: chals1.ais3.org:50001
Content-Type: application/json

{"spend":500,"rate":0.1234,"username":"Anonymous","gold":500,"score":0,"kills":0}
```


回傳格式如下：

```json
{
  "weapon": {
    "name": "Dagger III",
    "damage": 16.3,
    "maxDurability": 174,
    "range": 2.1,
    "angle": 39.0,
    "cooldown": 0.25,
    "bonusGoldPercent": 0.0,
    "lifestealPercent": 0.0
  },
  "armor": {
    "name": "Steel Armor",
    "slot": "Body",
    "damageReduction": 0.475,
    "bonusMaxHp": 47.5,
    "bonusSpeed": 0
  }
}
```


這個 JSON 會被 client 直接轉回 `WeaponData` / `ArmorData`，然後顯示在抽卡結果畫面上。

所以如果 server 願意把 flag 塞進 `weapon.name` 或 `armor.name`，client 會照單全收。

## 六、找出觸發條件

接著測不同的 `rate`：

- `rate = 0.2999`：正常裝備
- `rate = 0.3001`：`armor.name` 變成 flag
- `rate = 0.99`：一樣會回 flag
- `rate = -1` 或 `9.99`：回傳 `Cheater`

這代表 server 端大致上有這種邏輯：

- 明顯不合法的值直接標成作弊
- 但 `0.3 ~ 1.0` 之間的值卻被當成某種「不應該出現但仍可接受」的特殊條件

而這個特殊條件的獎勵就是 flag。

## 七、PoC

下面用 Python 直接重送請求即可：

```python
import requests

url = "http://chals1.ais3.org:50001"
payload = {
    "spend": 500,
    "rate": 0.3001,
    "username": "Anonymous",
    "gold": 0,
    "score": 0,
    "kills": 0,
}

r = requests.post(url, json=payload, timeout=5)
print(r.text)
```


實際回應重點如下：

```json
{
  "weapon": {
    "name": "Scythe III",
    "damage": 35.3,
    "maxDurability": 235,
    "range": 4.3,
    "angle": 72.0,
    "cooldown": 0.52,
    "bonusGoldPercent": 0.0,
    "lifestealPercent": 0.0
  },
  "armor": {
    "name": "AIS3{At_Least_U_DIDNT_MODIFY_MY_MONEY_RIGHT?}",
    "slot": "Body",
    "damageReduction": 0.0,
    "bonusMaxHp": 0.0,
    "bonusSpeed": 0.0
  }
}
```


也就是說 flag 被塞在：

```text
armor.name
```


## Flag

```text
AIS3{At_Least_U_DIDNT_MODIFY_MY_MONEY_RIGHT?}
```
{% endraw %}
