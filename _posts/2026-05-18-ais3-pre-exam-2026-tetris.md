---
title: "AIS3 Pre-Exam 2026 - tetris Writeup"
date: "2026-05-18 00:00:00 +0800"
categories: ["Reverse Engineering", "CTF Write-ups"]
tags: ["ctf", "ais3-pre-exam-2026", "reverse-engineering"]
description: "分析 Tetris 的隱藏驗證路徑、棋盤 pattern 與 RC4 解密流程。"
toc: true
source_url: "https://hackmd.io/4P3KgYwIRfW64wwA5gYXdw"
source_tag: "AIS3_Pre_exam 2026"
---

> 原始筆記：[HackMD](https://hackmd.io/4P3KgYwIRfW64wwA5gYXdw) · 比賽：AIS3 Pre-exam 2026

{% raw %}
> Category: Reverse  

---

## TL;DR

這題不是單純把 `strings` 拉出來就有 flag，而是把 flag 藏在一條遊戲內的隱藏驗證路徑裡。

- `sub_1668660` 不是 `main()`，它比較像 `__libc_start_main`。
- 真正的使用者入口是 `0x15C4017`，它只會印出開場畫面，然後進到 `sub_15C3EFA` 的 state machine。
- 遊戲裡存在一條隱藏分支，會檢查盤面前 4 列是否符合固定 pattern。
- 驗證成功後，程式會先產生 RC4 key，再解密 `.data` 裡的密文並印出 flag。

最終 flag：

```text
AIS3{T3tr1s_P4tt3rn_M4st3r!}
```


## 題目觀察

拿到執行檔之後先看 `start`。這段很標準：

```asm
404559  pop rsi
40455a  mov rdx, rsp
404568  mov rdi, offset loc_15C4017
40456f  call sub_1668660
```


也就是把 `loc_15C4017` 當成第一個參數傳進 `sub_1668660`。後面在 `sub_1668660` 裡又會把這個函式指標取出來，交給另一層 wrapper 以 `(argc, argv, envp)` 的形式呼叫，所以可以確定：

- `sub_1668660` 是啟動器，不是 `main`
- `loc_15C4017` 才是這支程式真正的入口

`loc_15C4017` 自己的工作很單純：

1. 印出 TETRIS 標題和控制說明
2. 等使用者按 Enter
3. 呼叫 `sub_15C3EFA`

所以真正的核心在 `sub_15C3EFA`。

## 主程式架構

`sub_15C3EFA` 本身不是遊戲邏輯，而是一個 state machine dispatcher。全域變數 `0x1AA89FC` 保存目前 state，`0x1AA8AA0` 是巨大的函式指標表。

高層流程大概是這樣：

```c
void game_main(void) {
    current_state = 0x57BC;
    dispatch(current_state);   // 初始化

    setup_terminal();

    while (!game_over) {
        current_state = 0x8323;
        dispatch_until_sentinel();
    }

    dispatch(game_over_state);
}
```


已知幾個重要 state：

- `0x57BC`：遊戲初始化
- `0x8323`：主迴圈 scheduler
- `0x1305B`：把目前方塊寫回盤面
- `0x157DA`：Game Over 收尾
- `0x16088`：印出隱藏訊息

分析到這裡還只看得出一般遊戲流程，flag 並不在正常結算畫面。

## 找隱藏分支

接著往按鍵處理函式 `0x15C3725` 看。這段有一個 jump table，除了明面上的移動和下落之外，還多了幾個沒寫在說明上的按鍵分支。

其中一條是：

- `O/o` -> `0x15C3A89`

這個分支會切到 state `0x1094B`，再進一步走到一串隱藏狀態。沿著這條鏈追下去，會到 `0x15C2EAB` 與 `0x15C2F4D`。

`0x15C2EAB` 會先初始化檢查用的計數器與旗標：

```c
row_idx = 0;
ok = 1;
current_state = 0x130CA;
```


真正的驗證在 `0x15C2F4D`。它會把 `board[row_idx][0..9]` 跟 `0x17371E0` 的固定資料逐格比較：

```c
if (row_idx > 3) {
    if (ok)
        current_state = 0x15C31;   // success
    else
        current_state = 0x2C5F;    // fail
} else {
    for (int col = 0; col <= 9; col++) {
        if (board[row_idx][col] != target[row_idx][col])
            ok = 0;
    }
    row_idx++;
    current_state = 0x130CA;
}
```


也就是說：

1. 先按隱藏按鍵 `O`
2. 程式開始檢查盤面前 4 列
3. 如果四列全部符合，就走 success path
4. 否則只會印出 `exit`

## 目標盤面

`0x17371E0` 這塊資料是一個 `4 x 10` 的整數矩陣：

```text
[5, 0, 5, 0, 1, 0, 4, 4, 4, 0]
[5, 5, 5, 0, 1, 0, 4, 0, 0, 0]
[5, 0, 5, 0, 1, 0, 0, 4, 4, 0]
[5, 0, 5, 0, 1, 0, 4, 4, 0, 3]
```


這裡的數字不是 ASCII，而是盤面上各格存的方塊 ID。`0` 代表空格，其它數字代表不同方塊或顏色。

所以「在遊戲內印出 flag」的條件可以直接寫成：

> 把盤面最上面的 4 列堆成上面這個 pattern，然後按 `O` 觸發隱藏檢查。

## Success Path 在做什麼

驗證成功後會走到 `0x15C30B5`。

這個函式做了兩件事：

1. 呼叫 `0x15C1A6E` 產生 24-byte key
2. 呼叫 `0x15C1C61` 解密密文，然後把結果交給 `0x15C317F` 印出來

### `0x15C1A6E`：從 target pattern 生成 key

這個函式會先對 `0x17371E0` 的 40 個 `dword` 做 FNV-1a：

```c
h = 0x811C9DC5;
for each dword x in target_matrix:
    h ^= x;
    h *= 0x1000193;
```


接著再用一個 LCG 把 32-bit state 展開成 24-byte key：

```c
key[i] = (h >> ((i % 4) * 8)) & 0xff;
h = (h * 0x41C64E6D + 0x3039) & 0x7fffffff;
```


### `0x15C1C61`：RC4

`0x15C1C61` 的樣子很明顯就是 RC4：

- 先初始化 `S[256] = {0..255}`
- 用 key 做 KSA
- 再逐 byte 產生 keystream XOR 密文

密文放在 `.data` 的 `0x1AA6130`，長度是 `0x1c = 28` bytes。

解完後的明文就是：

```text
AIS3{T3tr1s_P4tt3rn_M4st3r!}
```


## 本地還原腳本

如果不想真的把盤面堆出來，也可以直接把 binary 裡的 target matrix 與密文拉出來還原：

```python
from elftools.elf.elffile import ELFFile
from struct import unpack_from

path = "./tetris"

with open(path, "rb") as f:
    elf = ELFFile(f)
    ro = elf.get_section_by_name(".rodata")
    da = elf.get_section_by_name(".data")

    ro_base = ro["sh_addr"]
    da_base = da["sh_addr"]
    ro_data = ro.data()
    da_data = da.data()

target_addr = 0x17371E0
cipher_addr = 0x1AA6130

target_off = target_addr - ro_base
cipher_off = cipher_addr - da_base

target = [unpack_from("<I", ro_data, target_off + i * 4)[0] for i in range(40)]
cipher = bytearray(da_data[cipher_off:cipher_off + 0x1C])

# 0x15C1A6E
h = 0x811C9DC5
for x in target:
    h ^= x
    h = (h * 0x1000193) & 0xFFFFFFFF

key = bytearray()
for i in range(24):
    key.append((h >> ((i % 4) * 8)) & 0xFF)
    h = (h * 0x41C64E6D + 0x3039) & 0x7FFFFFFF

# 0x15C1C61 (RC4)
S = list(range(256))
j = 0
for i in range(256):
    j = (j + S[i] + key[i % len(key)]) & 0xFF
    S[i], S[j] = S[j], S[i]

i = 0
j = 0
plain = bytearray()
for b in cipher:
    i = (i + 1) & 0xFF
    j = (j + S[i]) & 0xFF
    S[i], S[j] = S[j], S[i]
    k = S[(S[i] + S[j]) & 0xFF]
    plain.append(b ^ k)

print(plain.decode())
```


執行結果：

```text
AIS3{T3tr1s_P4tt3rn_M4st3r!}
```


## 結論

這題有趣的地方不是演算法很難，而是作者把 flag 路徑藏在遊戲機制裡：

- 平常只會看到 Tetris 本體與 Game Over
- 真正的 flag route 需要走 undocumented key branch
- 驗證條件是盤面 pattern，不是單純的分數或清行數
- 成功後再用 target pattern 當材料生成 key，最後 RC4 解出 flag

一句話總結就是：
> 把盤面前四列排成指定 pattern，然後按 `O`，程式就會走 hidden success path，解密並印出 `AIS3{T3tr1s_P4tt3rn_M4st3r!}`。
{% endraw %}
