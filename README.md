# Eric — Security Research & Field Notes

使用 [Chirpy 7.6.0](https://github.com/cotes2020/jekyll-theme-chirpy/tree/v7.6.0)、Jekyll 與 GitHub Pages 建立的個人網站。

## 網站結構

- 首頁：個人簡介、研究入口與最新文章。
- `_tabs/about.md`：About，個人背景與聯絡連結。
- `_tabs/research.md`：Research，Fuzzing 研究方向。
- `_tabs/projects.md`：Projects，專案與 GitHub 入口。
- `_tabs/blog.html`：Blog，四個主題與所有文章。
- `_tabs/cv.md`：CV，學術背景與研究興趣。
- `_data/topics.yml`：Fuzzing、Reverse Engineering、Malware Analysis、CTF Write-ups。
- `_posts/`：公開文章；`_drafts/`：尚未公開的文章模板。

## 本機預覽

需要 Ruby 3.2 或更新的 3.x 版本，以及 Bundler。Windows 建議使用 RubyInstaller + Devkit，或依照 [Chirpy 官方說明](https://chirpy.cotes.page/posts/getting-started/) 使用 Dev Container。

```sh
bundle install
bundle exec jekyll serve
```

開啟 `http://127.0.0.1:4000`。修改 `_config.yml` 後需要重新啟動。

正式建置與內部連結檢查：

```sh
JEKYLL_ENV=production bundle exec jekyll build
bundle exec htmlproofer _site --disable-external
```

PowerShell 的正式建置環境變數寫法為 `$env:JEKYLL_ENV = 'production'`，再執行 `bundle exec jekyll build`。

## GitHub Pages 部署

1. 將變更提交並推送到這個 repository 的 `main` 分支。
2. 在 GitHub 的 **Settings → Pages → Build and deployment → Source** 選擇 **GitHub Actions**。
3. `Build and Deploy` workflow 會建置網站、檢查內部連結，再部署到 `https://eric-0522.github.io`。

Pull request 只執行建置與檢查，不會部署。網站設定使用空的 `baseurl`，適用於此個人網站 repository。

## 新增文章

將對應的 `_drafts/` 模板複製到 `_posts/YYYY-MM-DD-short-title.md`，填入真實內容、標題、摘要與時間後再發布。預設建置不會公開 `_drafts/`。

```yaml
---
title: 文章標題
date: 2026-10-03 12:00:00 +0800
categories: [Reverse Engineering, CTF Write-ups]
tags: [reverse-engineering]
description: 一句話說明文章內容。
toc: true
---
```

Blog 依照 `categories` 精確名稱分類；文章可以同時出現在 Reverse Engineering 和 CTF Write-ups。`tags` 使用小寫英文與連字號。程式碼使用 fenced code block 並指定語言；流程圖可在 front matter 加入 `mermaid: true`。

## HackMD CTF 筆記

已匯入 HackMD 的 `is1abCTF2025-writeup`（13 篇）及 `AIS3_Pre_exam 2026`（12 篇），共 25 篇。文章保留原文與程式碼，每篇均附 HackMD 來源連結；原有 81 張圖片保存於 `assets/img/writeups/`。

Blog 提供兩場比賽的標籤入口。文章日期沿用匯入時 HackMD 列表顯示的日期，不代表已確認的首次發表時間。原始標籤另記錄於文章的 `source_tag`，網站標籤則使用 `is1ab-ctf-2025` 與 `ais3-pre-exam-2026`。

`dg-server-rev` 原文的 8 個 `screenshot placeholder` 並未附上圖片，保留為 Markdown 原始碼註解，避免公開頁面顯示破圖。兩篇 dg-server 筆記的 3 處 Windows 本機腳本連結改為檔名與未附檔說明；原文內嵌的程式碼仍完整保留。HackMD 的 `python=` 程式碼區塊轉為 Jekyll 支援的 `python`，並保護程式碼中的 Liquid 符號。

## HackMD T5Camp 筆記

已匯入「T5Camp 2026 惡意程式分析」，歸入 Malware Analysis。文章保留原文與 HackMD 來源，62 張分析截圖保存於 `assets/img/t5camp-2026/`；日期沿用 HackMD 閱讀頁顯示的最後編輯日期（2025-11-30）。原文末尾只有 `malwa2 分析` 標題，未另行補寫內容。

## 個人資料補充清單

- [ ] 確認公開顯示名稱；目前使用 Eric 與已知 GitHub 帳號。
- [ ] 在 About 和 CV 加入學校、系所、就讀期間、實驗室與指導教授。
- [ ] 加入公開聯絡信箱；填入 `_config.yml` 的 `social.email`，並在 `_data/contact.yml` 啟用 email 項目。
- [ ] 在 Research 加入實際題目、研究對象、方法與可以公開的成果。
- [ ] 在 Projects 加入實際專案名稱、介紹、使用方式與 repository 連結。
- [ ] 在 CV 補充已確認的競賽、發表、實習或工作經歷；有正式 PDF 後再新增下載連結。
- [ ] 選擇文章授權方式；目前保留 Chirpy 的預設 CC BY 4.0 文案。

未提供的個人資訊以原始碼註解記錄，不會在公開頁面顯示「待補」欄位。專案列表目前只有 GitHub 入口，沒有加入未確認的成果。

## 維護與樣式

- `_config.yml`：網站名稱、網址、語言、時區、SEO 與主題設定。
- `assets/css/jekyll-theme-chirpy.scss`：Chirpy 官方樣式入口；`_sass/custom.scss`：首頁、主題索引與青色點綴。
- `_layouts/home.html`：沿用 Chirpy 7.6.0 首頁版型，加入首頁內容插槽；升級主題時請與上游版型比較。
- `assets/img/`：本機頭像與 favicon。

原有 `cmdline_analysis.ipynb` 保留在 repository，預設不輸出到公開網站。開發環境與驗證資料位於 git 忽略的 `.build-support/`，不會被發布。

Chirpy 主題依 MIT License 發布，來源與版權資訊保留於 `THIRD_PARTY_NOTICES.md`。
