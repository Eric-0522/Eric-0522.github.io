---
title: "AIS3 Pre-Exam 2026 luac_stripped.exe Writeup"
date: "2026-05-18 00:00:00 +0800"
categories: ["Reverse Engineering", "CTF Write-ups"]
tags: ["ctf", "ais3-pre-exam-2026", "reverse-engineering"]
description: "還原修改過的 Lua 5.1 opcode mapping 與 secret.luac bytecode。"
toc: true
source_url: "https://hackmd.io/Knl4iGySRomHyXbSUK62vw"
source_tag: "AIS3_Pre_exam 2026"
---

> 原始筆記：[HackMD](https://hackmd.io/Knl4iGySRomHyXbSUK62vw) · 比賽：AIS3 Pre-exam 2026

{% raw %}
> Category: Reverse

---

## Information

- Category: Reverse
- Challenge file: `luac_stripped.exe`
- Extra file: `secret.luac`
- Final flag: `AIS3{Lu4_0pc0d3_Shuffl1ng_1s_Fun}`

## TL;DR

這題表面上是在拆一個被 strip 過的 `luac`，題目提示也很直接:

```text
This compiler has been disabled for the CTF challenge.
Reverse engineer this binary to discover the OpCode mapping!
```


一開始很容易把重點放在 `main()`，但其實 `main()` 只是印提示字串。真正的考點有三層:

1. `luaP_opnames` 被改成 `OP_00 ~ OP_37`，必須自己還原 Lua 5.1 opcode mapping。
2. 寫入 bytecode 時，opcode 的 low 6 bits 還會再依照 `pc` 和一個 per-function key 做編碼。
3. `secret.luac` 的 prototype header 也不是完全標準 Lua 5.1，多了一個 1-byte key。

把這三層都拆掉之後，就可以把 `secret.luac` 反組譯成接近可讀的 Lua VM 指令，再直接把 checker 邏輯翻出來。

## Recon

先看 `main`:

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  _main(argc, argv, envp);
  puts("This compiler has been disabled for the CTF challenge.");
  puts("Reverse engineer this binary to discover the OpCode mapping!");
  return 0;
}
```


所以主程式沒有真正做驗證，接下來就把注意力放回 Lua runtime/compiler 本體。

在 `.rdata` 可以看到:

- `luaP_opmodes`
- `luaP_opnames`
- 一整串 `OP_00`, `OP_01`, ..., `OP_37`

這表示題目把原本 Lua 5.1 的 opcode 名稱藏起來了，但 codegen 和 VM 還是照新的編號工作。

## Step 1: Recover opcode mapping

這一段最穩的作法不是硬看 `luaV_execute` 的 38 個 case，而是從 compiler codegen 端回推。

例如:

- `luaK_nil` 直接組出 opcode `7`，所以 `OP_07 = LOADNIL`
- `luaK_ret` 直接組出 opcode `30`，所以 `OP_30 = RETURN`
- `luaK_jump` 直接組出 opcode `10`，所以 `OP_10 = JMP`
- `luaK_setlist` 直接組出 opcode `33`，所以 `OP_33 = SETLIST`
- `funcargs` 會用 opcode `28` 生成 call，所以 `OP_28 = CALL`
- `leaveblock` 會生成 opcode `34`，所以 `OP_34 = CLOSE`
- `subexpr` 的 `...` 路徑會生成 opcode `36`，所以 `OP_36 = VARARG`

把 `luaK_*`, `codearith`, `codecomp`, `forbody`, `funcargs`, `leaveblock` 一路補完之後，可以還原完整 mapping:

```text
OP_00 -> TFORLOOP
OP_01 -> ADD
OP_02 -> MOVE
OP_03 -> UNM
OP_04 -> LOADK
OP_05 -> LOADBOOL
OP_06 -> CONCAT
OP_07 -> LOADNIL
OP_08 -> SUB
OP_09 -> GETUPVAL
OP_10 -> JMP
OP_11 -> GETGLOBAL
OP_12 -> GETTABLE
OP_13 -> SETGLOBAL
OP_14 -> SETUPVAL
OP_15 -> MUL
OP_16 -> SETTABLE
OP_17 -> DIV
OP_18 -> MOD
OP_19 -> NEWTABLE
OP_20 -> SELF
OP_21 -> POW
OP_22 -> LEN
OP_23 -> LT
OP_24 -> TEST
OP_25 -> LE
OP_26 -> TESTSET
OP_27 -> EQ
OP_28 -> CALL
OP_29 -> TAILCALL
OP_30 -> RETURN
OP_31 -> FORLOOP
OP_32 -> FORPREP
OP_33 -> SETLIST
OP_34 -> CLOSE
OP_35 -> CLOSURE
OP_36 -> VARARG
OP_37 -> NOT
```


## Step 2: Find the real opcode encoding

只還原 mapping 還不夠，因為題目在寫 bytecode 時又多做了一層混淆。

看 `luaK_code`:

```c
*(_DWORD *)(code + 4 * pc) =
    ins & 0xFFFFFFC0 |
    ((unsigned __int8)(15 * pc + 17) ^
     (unsigned __int8)(ins ^ *(BYTE *)(proto + 113) ^ 0x2B)) & 0x3F;
```


也就是說，真正寫進 instruction 的 low 6 bits 不是 plain opcode，而是:

```text
encoded_op =
    ((15 * pc + 17) ^ plain_op ^ key ^ 0x2B) & 0x3F
```


反過來 decode 也很簡單:

```text
plain_op =
    ((15 * pc + 17) ^ encoded_op ^ key ^ 0x2B) & 0x3F
```


這裡的 `key` 就是 prototype header 裡那個額外塞進去的 1-byte 值。

## Step 3: Parse the modified `secret.luac`

`luaU_undump` 和它呼叫的 loader 會暴露格式細節。

觀察 loader 可以知道:

- chunk header 還是標準 Lua 5.1 的 12-byte header
- string / integer / prototype layout 大致沿用 Lua 5.1
- 但在 `line_defined`, `last_line_defined` 後面，不是標準的 4 bytes header
- 它變成 5 bytes:

```text
[nups, key, numparams, is_vararg, maxstacksize]
```


所以如果直接拿一般 Lua 5.1 parser 去讀，offset 會整個錯掉。

我後來用一個最小 parser 把 prototype 解開，再配合前面的 opcode decode 公式做反組譯。

## Step 4: Understand helper functions

`secret.luac` 的頂層 prototype 會先建立幾個 inner closures，其中最重要的是:

- `main.0`: 兩數 XOR
- `main.1`: 交錯合併兩個 array
- `main.2`: 對 array 做簡單線性變換
- `main.3`: 生成 `k1`
- `main.4`: 生成 `k2`
- `main.5`: 真正的 checker

其中 `main.0` 一開始我看錯，以為是 bitwise XNOR，後來用自己寫的最小 VM 跑幾組測資才確認它其實是 XOR。

這個坑很重要，因為如果把 `main.0` 誤判成 XNOR，後面的每一位反推都會得到另一組看起來很像答案、但最後無法通過 checker 的垃圾資料。

## Step 5: Reconstruct the checker

把 `main.3` 和 `main.4` 跑完之後可以先得到兩個表:

```python
k1 = [23, 88, 41, 199, 17, 90, 250, 61, 143, 12, 77]
k2 = [158, 35, 172, 11, 160, 217, 123, 62, 248, 242, 88, 51, 84,
      125, 92, 152, 46, 62, 166, 147, 23, 73, 80, 220, 153, 6,
      67, 13, 195, 5, 91, 6, 32]
```


checker 的核心流程可以整理成:

```python
rolling = 65

for i in range(1, len(inp) + 1):
    x = k1[((i * 5) + rolling) % len(k1)]
    t1 = xor(inp[i - 1] + i + rolling, x + i * 7)
    t2 = xor(x, i)
    t  = (t1 + (t2 % 13)) % 256

    if t != k2[i - 1]:
        return False

    rolling = (rolling + t + x + i * 3) % 256

return rolling == 229
```


重點在於:

- `rolling` 每一輪都會更新
- 下一輪又會拿 `rolling` 去選 `k1` 的 index
- 所以這不是單純「每一位獨立」的 byte-wise transform

不過這裡仍然可以從前往後唯一反推，因為每一輪:

- 當前 `rolling` 已知
- `x` 已知
- `k2[i]` 已知
- 只剩當前輸入 byte 未知

實際跑出來每一輪都只有唯一解。

## Step 6: Recover the flag

照前面的遞推做逐位反推，會得到:

```text
AIS3{Lu4_0pc0d3_Shuffl1ng_1s_Fun}
```


最後再丟回 checker 驗證，結果為 `True`。

## Solve script

下面放精簡版的核心反推程式。完整 parser / mini VM 我是另外寫在本地腳本裡處理，這裡只保留最終解 flag 的關鍵邏輯。

```python
def bxor(x, y):
    return x ^ y

k1 = [23, 88, 41, 199, 17, 90, 250, 61, 143, 12, 77]
k2 = [
    158, 35, 172, 11, 160, 217, 123, 62, 248, 242, 88,
    51, 84, 125, 92, 152, 46, 62, 166, 147, 23, 73,
    80, 220, 153, 6, 67, 13, 195, 5, 91, 6, 32
]

rolling = 65
flag = []

for i, target in enumerate(k2, start=1):
    x = k1[((i * 5) + rolling) % len(k1)]
    rhs = bxor(x, i) % 13

    found = None
    for b in range(256):
        t1 = bxor((b + i + rolling) % 256, (x + i * 7) % 256)
        t = (t1 + rhs) % 256
        if t == target:
            found = b
            break

    assert found is not None
    flag.append(found)
    rolling = (rolling + target + x + i * 3) % 256

flag = bytes(flag)
assert rolling == 229
print(flag.decode())
```


輸出:

```text
AIS3{Lu4_0pc0d3_Shuffl1ng_1s_Fun}
```


## Flag

```text
AIS3{Lu4_0pc0d3_Shuffl1ng_1s_Fun}
```


## Notes

這題最有趣的地方不是單純把 Lua opcode 順序打亂，而是把三件事疊在一起:

1. `opname` 被抽掉
2. opcode low 6 bits 做了 per-`pc` 編碼
3. chunk prototype header 也做了格式修改

如果只做第一層，IDA 裡追一追很快就能把 mapping 拼回來；真正讓這題變麻煩的是第二層和第三層。

另外，checker 雖然最後看起來像一般的 byte-by-byte 驗證，但中間那個 rolling state 會影響下一輪選到的 `k1` 值，這也是最容易手推錯的地方。
{% endraw %}
