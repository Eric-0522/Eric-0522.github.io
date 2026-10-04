---
title: "AIS3 Pre-exam 2026- hidden-in-the-cloak Writeup"
date: "2026-05-18 00:00:00 +0800"
categories: ["Reverse Engineering", "CTF Write-ups"]
tags: ["ctf", "ais3-pre-exam-2026", "reverse-engineering"]
description: "解析 Unity 資源與 Spine slot 順序，還原藏在角色披風中的 flag。"
toc: true
source_url: "https://hackmd.io/QVovVl69QCy9wGM0t70R7Q"
source_tag: "AIS3_Pre_exam 2026"
---

> 原始筆記：[HackMD](https://hackmd.io/QVovVl69QCy9wGM0t70R7Q) · 比賽：AIS3 Pre-exam 2026

{% raw %}
> Category: Reverse

---

## 題目敘述

題目給了一個 Unity 遊戲發行包，flag 格式為 `AIS3{...}`。  
一開始看起來像是要逆遊戲邏輯、抽卡系統或遠端 API，但實際上真正的 flag 藏在角色素材的披風裡。

## TL;DR

1. 先確認這是一個 Unity 遊戲，核心邏輯在 `Assembly-CSharp.dll`。
2. 逆過程中會看到 `GachaServer`、`ShopUI`、`PlayerStats` 等類別，看起來很像主線。
3. 但題名叫 `hidden-in-the-cloak`，而且角色素材被打包在 `character_main` bundle 裡，這提示「披風」本身可能有東西。
4. 解開 `character_main` 後可以拿到：
   - `character.png`
   - `character.atlas`
   - `character.json`
5. `character.png` 上有很多文字碎片，`character.json` 則告訴我們這些碎片在 Spine 骨架中的實際排列順序。
6. 依照 slot 順序把文字拼回去，就得到 flag。

## 先看檔案結構

題目目錄裡可以看到這是一包標準 Unity Windows build：

```text
Reverse1.exe
UnityPlayer.dll
Reverse1_Data/
  Managed/Assembly-CSharp.dll
  StreamingAssets/bundles/character_main
```


這類題目通常先看兩個地方：

1. `Assembly-CSharp.dll`
2. `StreamingAssets` / asset bundle

## 一開始的誤導點

把 `Assembly-CSharp.dll` 拿去看 type name，很快就能看到：

```text
GachaServer
GachaUI
ShopUI
PlayerStats
SpawnManager
BackgroundBuilder
UsernameUI
WeaponData
ArmorData
```


其中最顯眼的是 `GachaServer`。  
繼續看 IL 會發現：

- 預設 server URL 是 `http://chals1.ais3.org:50001`
- 抽卡時會 POST 一份 JSON
- 失敗時會走 `LocalFallback`

送出的 JSON 大概長這樣：

```json
{
  "spend": 500,
  "rate": 0.1234,
  "username": "Anonymous",
  "gold": 0,
  "score": 0,
  "kills": 0
}
```


這一段很容易讓人以為解法是：

- 找抽卡邏輯漏洞
- 刷特殊武器
- 或直接從遠端服務拿 flag

我也實際驗證過這條路，server 真的會回不同武器與護甲，甚至會出現像下面這種明顯的特殊分支：

```json
{
  "weapon": {
    "name": "Wet Noodle I",
    "damage": 0.1,
    "maxDurability": 1
  },
  "armor": {
    "name": "Cheater",
    "slot": "Body",
    "bonusMaxHp": -100
  }
}
```


但這些都沒有直接吐 flag，反而更像作者故意放的煙霧彈。

## 題名才是提示

題名叫 `hidden-in-the-cloak`。  
既然是 Unity 遊戲，而且角色素材另外打成 bundle，很自然就會想到：

- `hidden`
- `cloak`
- `character_main`

有沒有可能 flag 根本不是在邏輯裡，而是藏在角色美術素材？

## 解包角色素材

`character_main.manifest` 可以看出這包裡面是角色 Spine 資料：

```text
Assets/SpineData/character.json
Assets/SpineData/character.atlas.txt
Assets/SpineData/character.png
Assets/Prefabs/CharacterSpine.prefab
```


這時候直接把 bundle 解開即可。  
我用 `UnityPy` 處理：

```python
from UnityPy import Environment
from pathlib import Path

bundle = Path(r"Reverse1_Data/StreamingAssets/bundles/character_main")
env = Environment()
env.load_file(str(bundle))

for obj in env.objects:
    data = obj.read_typetree()
    if obj.type.name == "TextAsset":
        print(data.get("m_Name"))
```


可以拿到兩個關鍵 TextAsset：

- `character`
- `character.atlas`

另外還能匯出貼圖 `character.png`。

## 看到披風上的字

把角色貼圖匯出後，會發現圖上不是正常角色貼圖，而是很多文字碎片。

像這些：

```text
AIS3{
d0n7_70
uch_my_
c4p3_0k_
b
3
f
1
e
7
6
8
}
```


如果只看貼圖本身，字的順序是亂的，因為作者不是把整串 flag 直接畫成一張圖，而是：

1. 把字拆成很多小塊
2. 放進 atlas
3. 再由 Spine 骨架用多個 slot 掛上去

所以接下來不能只靠肉眼，要看 `character.json`。

## 真正的重點在 `character.json`

`character.json` 裡有一大段 `slots` 與 `skins.attachments`。  
其中有一串 slot 很可疑：

```text
s013 -> r037 -> AIS3{
s014 -> r017 -> d0n7_70
s015 -> r016 -> uch_my_
s016 -> r034 -> c4p3_0k_
s017 -> r047 -> b
s018 -> r031 -> 3
s019 -> r050 -> f
s020 -> r032 -> 1
s021 -> r022 -> e
s022 -> r039 -> 7
s023 -> r058 -> 6
s024 -> r043 -> 8
s025 -> r042 -> }
```


這裡其實已經直接告訴我們 flag 的排列順序了。

把它們串起來：

```text
AIS3{
+ d0n7_70
+ uch_my_
+ c4p3_0k_
+ b
+ 3
+ f
+ 1
+ e
+ 7
+ 6
+ 8
+ }
```


得到：

```text
AIS3{d0n7_70uch_my_c4p3_0k_b3f1e768}
```


## 重現腳本

下面是一個最小版的重現概念，核心是去讀 `character` 這個 Spine JSON，然後把 `s013` 到 `s025` 的 attachment 依序拼起來。

```python
import json

mapping = {
    "r016": "uch_my_",
    "r017": "d0n7_70",
    "r022": "e",
    "r031": "3",
    "r032": "1",
    "r034": "c4p3_0k_",
    "r037": "AIS3{",
    "r039": "7",
    "r042": "}",
    "r043": "8",
    "r047": "b",
    "r050": "f",
    "r058": "6",
}

with open("character.json", "r", encoding="utf-8") as f:
    data = json.load(f)

attachments = data["skins"][0]["attachments"]
ans = []

for slot in data["slots"][12:25]:
    slot_name = slot["name"]
    att_name = slot["attachment"]
    path = attachments[slot_name][att_name]["path"]
    ans.append(mapping[path])

print("".join(ans))
```


## Flag

```text
AIS3{d0n7_70uch_my_c4p3_0k_b3f1e768}
```
{% endraw %}
