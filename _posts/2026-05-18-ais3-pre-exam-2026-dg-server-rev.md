---
title: "AIS3 Pre-exam 2026 -dg-server-rev Writeup"
date: "2026-05-18 00:00:00 +0800"
categories: ["Reverse Engineering", "CTF Write-ups"]
tags: ["ctf", "ais3-pre-exam-2026", "reverse-engineering"]
description: "逆向自製 NSEC6 機制，從 owner hash 還原 label 並進行 zone walking。"
toc: true
source_url: "https://hackmd.io/PENLfwCNRuOFE_GJiuZbrQ"
source_tag: "AIS3_Pre_exam 2026"
---

> 原始筆記：[HackMD](https://hackmd.io/PENLfwCNRuOFE_GJiuZbrQ) · 比賽：AIS3 Pre-exam 2026

{% raw %}
> Category: Reverse  
> Files: `dg-server`, `scripts/dg-verify.py`

---


## TL;DR

這題表面上是 DNSSEC / DoH 題，但真正要 reverse 的是 binary 自製的 `NSEC6` 機制。  
重點不是直接爆破子網域，而是：

1. 找出 server 實際支援的 record type
2. reverse `NSEC6` 的 state 與 owner hash 生成方式
3. 發現這題的 `z_mask` 退化成 `0xff * 20`
4. 因此可以把 `owner_hash` / `next_hash` 逆回 label
5. 用這個能力做 zone walking，最後找到藏 flag 的 `TXT`

最後 flag：

```text
AIS3{w4lking_0n_D0H_z0n3--NSEC...NSEC6!_666~~~}
```


---


## Table of Contents

- [Challenge Info](#challenge-info)
- [Initial Recon](#initial-recon)
- [What `dg-verify.py` Actually Verifies](#what-dg-verifypy-actually-verifies)
- [Binary Triage](#binary-triage)
- [Observing `NXDOMAIN` and `NSEC6`](#observing-nxdomain-and-nsec6)
- [Reversing the `NSEC6` State](#reversing-the-nsec6-state)
- [Reversing the Owner Hash](#reversing-the-owner-hash)
- [Zone Walking Strategy](#zone-walking-strategy)
- [Solver Script](#solver-script)
- [Key Insights](#key-insights)
- [Flag](#flag)

---


## Challenge Info

題目給的互動方式：

```bash
python3 dg-verify.py @chals1.ais3.org:53573 www.curious.sleeping A
```


手上有兩個主要檔案：

- `dg-server`
- `scripts/dg-verify.py`

我一開始的做法很標準：

1. 先看官方 verifier 在驗什麼
2. 再用 IDA 看 binary 實際支援什麼

<!-- HackMD screenshot placeholder: screenshot placeholder: challenge files / folder tree (./images/dg-server-rev-files.png) -->

---


## Initial Recon

`dg-server` 是一個 Linux x86-64 ELF binary。  
它會處理類似 DoH 的 HTTP request，請求格式大致是：

```text
GET /dns-query?name=<domain>&type=<rrtype>
```


從 verifier 的角度看，題目像是在做 DNSSEC chain 驗證；但對 reverse 題來說，這通常只是表層介面，真正重點在 binary 額外實作的那一段。

---


## What `dg-verify.py` Actually Verifies

先讀 `scripts/dg-verify.py` 會發現它在驗下面這條 trust chain：

- `.` 的 `DNSKEY`
- `sleeping.` 的 `DS` / `DNSKEY`
- `curious.sleeping.` 的 `DS` / `DNSKEY`
- 最後驗 `www.curious.sleeping. A`

也就是說，它把整個服務當成一個 DNSSEC-like authoritative setup。

但這裡有一個很重要的限制：

```python
if rrtype not in {"A", "NS", "MX"}:
    raise ValueError("dg-verify only supports A, NS, and MX")
```


這段只說明 verifier 只會驗 `A / NS / MX`，不代表 server 只支援這幾種。

這種題型很常見：

- verifier 很保守
- 真正的突破點藏在 binary 額外支援的功能裡

<!-- HackMD screenshot placeholder: screenshot placeholder: verifier code highlighting supported RR types (./images/dg-server-rev-verifier-types.png) -->

---


## Binary Triage

把 `dg-server` 丟進 IDA 後，很快可以從字串與 type dispatch 看出它支援的 record type 比 verifier 多很多：

- `A`
- `NS`
- `MX`
- `TXT`
- `SOA`
- `DS`
- `RRSIG`
- `DNSKEY`
- `NSEC6`

其中最顯眼的就是 `NSEC6`。

正常 DNSSEC 常見的是：

- `NSEC`
- `NSEC3`

這題自己造了一個 `NSEC6`，基本上就是在說「這裡有題目要你看」。

<!-- HackMD screenshot placeholder: screenshot placeholder: IDA pseudocode or strings showing supported RR types (./images/dg-server-rev-supported-types.png) -->

---


## Observing `NXDOMAIN` and `NSEC6`

先對 zone apex 打幾個查詢：

```text
curious.sleeping. SOA
curious.sleeping. DNSKEY
curious.sleeping. NS
curious.sleeping. MX
```


可以先拿到：

- `SOA serial`
- zone 的 `DNSKEY`
- 幾個已知 label，例如 `www`、mail / NS 對應的名稱

接著故意查不存在的名稱：

```text
nope.curious.sleeping. A
```


這時候回應不是單純的 `NXDOMAIN`，而是附上一筆 `NSEC6`：

```text
<owner> NSEC6 2e 426 0009 73311337 <next-hash> <type-bitmap>
```


馬上可以看出幾個特徵：

- salt 是固定的 `73311337`
- 有三個固定參數：`2e 426 0009`
- `owner` 與 `next` 不是明文 label，而是某種編碼後的值

所以這題的主線就很清楚了：

1. reverse `NSEC6`
2. 從 `owner_hash` / `next_hash` 還原真實 label
3. 用這些 label 繼續往下走
4. 找出隱藏的 `TXT`

<!-- HackMD screenshot placeholder: screenshot placeholder: sample NXDOMAIN response with NSEC6 (./images/dg-server-rev-nsec6-response.png) -->

---


## Reversing the `NSEC6` State

Binary 內和 `NSEC6` 有關的邏輯，核心可以拆成兩塊：

1. 建立 zone-specific state
2. 用這個 state 對 label 做變換

我把這段 reverse 後的結果整理到了 `solve_dg_server_rev.py`（原筆記中的本機檔案，未附於 HackMD）。

### Step 1: Build zone state

這段會用：

- `SOA serial`
- zone name
- `DNSKEY` raw public key

去建出兩個 20-byte mask：

- `z_mask`
- `y_mask`

最容易踩的坑是這裡：

- 不能直接拿 `DNSKEY` 的 base64 字串去算
- 必須先 base64 decode，拿 raw public key bytes

我還原後的核心邏輯大致如下：

```python
def build_zone_state(zone: str, serial: int, dnskeys: list[Dnskey]) -> ZoneState:
    z_mask = bytearray(
        (0x4380B311C5D51483).to_bytes(8, "little")
        + (0x918DAB0D7023AAFB).to_bytes(8, "little")
        + (0xA450E054).to_bytes(4, "little")
    )
    v4 = (serial ^ 0x6E736563) & 0xFFFFFFFF
    for key in dnskeys:
        tail = key.public_raw[-20:]
        for idx in range(20):
            z_mask[idx] ^= tail[idx]
        v5 = (key.algorithm ^ (key.protocol << 8) ^ (key.flags << 16) ^ v4) & 0xFFFFFFFF
        v2 = hmix(zone.encode(), v5)
        v4 = hmix(key.public_raw, v2)
    v6 = hmix(b"73311337", (v4 ^ 0xD262E) & 0xFFFFFFFF)
```


後面再從 `v6` 展開成 `y_mask`。

### Step 2: The intended weakness

真正的關鍵在這裡。

把 `curious.sleeping.` 的 state 算出來之後，會發現：

```python
state.z_mask == b"\xff" * 20
```


這不是一般情況，而是題目故意設計的弱點。

本來 `owner_hash` 看起來像某種不可逆結果，但當 `z_mask` 全部都是 `0xff`，後面的運算就退化成可逆形式。也就是說，這題不是要你猜子網域，而是要你看懂 binary，然後把 `NSEC6` 反過來解。

<!-- HackMD screenshot placeholder: screenshot placeholder: debugger or script output showing z_mask = ff..ff (./images/dg-server-rev-zmask-all-ff.png) -->

---


## Reversing the Owner Hash

`owner_hash` 使用的是一個自訂 base32 alphabet：

```text
0123456789ABCDEFGHIJKLMNOPQRSTUV
```


所以流程是：

1. 先 base32 decode
2. 再把 binary 裡的 permutation 倒著做回來
3. 最後把加法 carry 那一步補回去

逆回去的核心長這樣：

```python
def invert_nsec6_owner(owner_hash: str, state: ZoneState) -> str:
    if state.z_mask != b"\xFF" * 20:
        raise ValueError("this solver expects the challenge's all-0xff NSEC6 mask")

    data = decode_nsec6_base32(owner_hash)

    for round_idx in range(8, -1, -1):
        for idx in range(20):
            data[idx] = ((data[idx] - (17 * round_idx + idx)) & 0xFF) ^ state.y_mask[(round_idx + idx) % 20]
        first = data[0]
        for idx in range(19):
            data[idx] = data[idx + 1]
        data[19] = first

    for idx in range(19, -1, -1):
        data[idx] = (data[idx] + 1) & 0xFF
        if data[idx] != 0:
            break

    label_len = data[0]
    return bytes(data[1 : 1 + label_len]).decode()
```


最後解出來的是第一層 label，例如：

- `www.curious.sleeping.` 會還原出 `www`
- `api.curious.sleeping.` 會還原出 `api`

這點很重要，因為後面做 zone walking 時，我們只要在 apex 下拼回去就好。

<!-- HackMD screenshot placeholder: screenshot placeholder: example owner_hash reversed back to label (./images/dg-server-rev-owner-reverse.png) -->

---


## Zone Walking Strategy

接下來就是把這個能力變成自動化。

我的做法是：

1. 先拿已知 label 當起點
   - apex `curious`
   - `www`
   - `NS` 指到的 label
   - `MX` 指到的 label
2. 對每個候選 label 查：
   - `A`
   - `TXT`
   - `NS`
   - `MX`
3. 如果查不到，server 會回 `NXDOMAIN + NSEC6`
4. 把其中的 `owner_hash` 與 `next_hash` 逆成新 label
5. 新 label 再塞回 queue，繼續走

對應程式邏輯如下：

```python
def discover_hidden_labels(host: str, port: int, state: ZoneState, timeout: float) -> tuple[dict[str, set[str]], str]:
    discovered_types: dict[str, set[str]] = {}
    pending = [state.apex_label]

    ns_line = find_record_line(query(host, port, state.zone, "NS", timeout), "NS")
    mx_line = find_record_line(query(host, port, state.zone, "MX", timeout), "MX")

    pending.append(parse_target_name_from_record(ns_line).split(".", 1)[0])
    pending.append(parse_target_name_from_record(mx_line).split(".", 1)[0])
    pending.append("www")

    seen: set[str] = set()

    while pending:
        label = pending.pop(0)
        if label in seen:
            continue
        seen.add(label)
        fqdn = label_to_fqdn(label, state)

        for rrtype in ("A", "TXT", "NS", "MX"):
            lines = query(host, port, fqdn, rrtype, timeout)
            direct = find_record_line(lines, rrtype)
            if direct is not None:
                if rrtype == "TXT" and "AIS3{" in extract_txt_value(direct):
                    return discovered_types, extract_txt_value(direct)
                continue

            if lines and lines[0].startswith("NXDOMAIN "):
                nsec6 = parse_nsec6(lines)
                owner_label = invert_nsec6_owner(nsec6.owner_hash, state)
                next_label = invert_nsec6_owner(nsec6.next_hash, state)
                pending.append(owner_label)
                pending.append(next_label)
                break
```


最後走出來的隱藏 label 包括：

- `api`
- `ftp`
- `_dmarc`
- `status`
- `azft0azxct7utcyw`

其中最可疑的是這個：

```text
azft0azxct7utcyw.curious.sleeping. TXT
```


一查就直接出 flag。

<!-- HackMD screenshot placeholder: screenshot placeholder: walking result / discovered labels (./images/dg-server-rev-zone-walking.png) -->

---


## Solver Script

完整 solver 在：

- `solve_dg_server_rev.py`（原筆記中的本機檔案，未附於 HackMD）

直接跑：

```bash
python solve_dg_server_rev.py
```


或指定 endpoint：

```bash
python solve_dg_server_rev.py --host chals1.ais3.org --port 53573 --zone curious.sleeping.
```


這支腳本會自動：

1. 取 `SOA`
2. 取 `DNSKEY`
3. 重建 `z_mask` / `y_mask`
4. reverse `owner_hash`
5. 做 zone walking
6. 找到含有 `AIS3{` 的 `TXT`

執行成功時會印出：

```text
zone: curious.sleeping.
labels: _dmarc, api, azft0azxct7utcyw, curious, ftp, status, www
AIS3{w4lking_0n_D0H_z0n3--NSEC...NSEC6!_666~~~}
```


<!-- HackMD screenshot placeholder: screenshot placeholder: solver output (./images/dg-server-rev-solver-output.png) -->

---


## Key Insights

這題我覺得最關鍵的點有三個。

### 1. 不要被 `dg-verify.py` 限制住

Verifier 只驗 `A / NS / MX`，但 binary 實際支援 `TXT` 和 `NSEC6`。  
真正的突破口就是 binary 的額外功能，而不是 verifier 公開暴露的那一小塊。

### 2. `DNSKEY` 一定要用 raw bytes

這點非常容易搞錯。

- 錯誤做法：拿 base64 字串直接算
- 正確做法：先 decode base64，再用 raw public key bytes 去算 state

這裡一錯，後面的 `z_mask` / `y_mask` 全部會歪掉。

### 3. `z_mask == 0xff * 20` 是整題的本質弱點

如果 `NSEC6` 真的是正常不可逆的設計，那最多只能洩漏很有限的資訊。  
但這題故意把 `z_mask` 設計到退化成全 `0xff`，使 owner hash 幾乎可以直接逆回 label。

所以這題本質上不是傳統 DNSSEC 題，而是：

- reverse 自製 record format
- 找出設計弱點
- 利用這個弱點把隱藏名稱整個 walking 出來

---


## Flag

```text
AIS3{w4lking_0n_D0H_z0n3--NSEC...NSEC6!_666~~~}
```
{% endraw %}
