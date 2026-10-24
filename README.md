# NELUUN V9｜安全連線開發版

**中文：內露恩**　**口號：與你，同在。**

這一版接續 V8，不覆蓋原「小樹家教」備份，也不覆蓋 V7 Worker 或 D1 資料庫。

## 完成範圍

- **個人助理**與**學習助理**兩個入口，按鈕皆為 **Enter**。沿用 V8 黑金／粉藍櫻桃紅的 UI、黑貓、題庫、待辦與筆記。
- 電子郵件六碼一次性驗證登入的 **Cloudflare Worker + D1 後端實作**，需設定 Resend 才能實際寄送信件。
- 驗證碼 10 分鐘有效、單次使用、限錯 5 次，寄送與驗證端有資料庫層級次數限制。
- 登入狀態採隨機 session token、HttpOnly / Secure / SameSite=Strict cookie；D1 只儲存加鹽（pepper）雜湊後的 session token。
- 伺服器端要求同來源 JSON POST；AI API key **只允許放在 Worker Secret**，不可寫進瀏覽器。
- 個人助理 `/api/chat` 實作：僅已登入、明確配置 `AI_ENABLED=true`、API Key 可用時才執行；每人每天 UTC 日期 5 次 D1 原子限制，單則字數 ≤800，回覆長度上限 350 tokens（依模型支援情況），不在 D1 保存聊天正文，呼叫 OpenAI Responses API 時設定 `store:false`。
- 家長**自行聲明／撤回**的伺服器紀錄。**這不等於監護人身分已驗證，也不足以單獨作為公開兒童雲端服務的法遵機制。**
- **兒童 AI 和兒童雲端資料同步沒有開放。**現有學習功能仍在本機，兒童訊息不送往 AI 供應商。
- 確保 Service Worker **不攔截/快取任何 `/api/*` 請求**。

## 現況與限制

**程式已完成，但目前不是已部署服務。**登入後端要在 Cloudflare 部署，並接上新的 D1 資料庫、已核准寄件網域（Resend）與必要 Secrets 才會運作。未設定時前端會顯示「登入尚未連線／未設定」，AI 維持本機範例，不會假裝已接通。

仍然需要驗證：正式網域、TLS、Resend 寄送設定、遠端 D1、真正的登入寄信、同時請求額度、費用上限、日誌／事故處理、兒童家長身分及法規。**每日 5 次請求限制不等於金額型「硬預算」**；需另外在 AI 供應商端設定專案預算或其他外部限制。

## 首次部署設定（Cloudflare 帳號持有人執行）

1. 在 Cloudflare 建立**新的** D1 資料庫 `neluun-v9`（避免改動 V7），取得其實際資料庫 ID。不要使用 V7 已有 DB。
2. 將 `wrangler.jsonc` 中 `REPLACE_WITH_NEW_D1_DATABASE_ID` 替換成新的實際 ID。
3. `npm install`，`npx wrangler login`，然後 `npm run db:remote`。這會把 `migrations/0001_init.sql` 套用到 **V9 新資料庫**。
4. 設定 Secrets（請在 Cloudflare/Wrangler 端輸入，**不要貼在聊天或 commit 到 GitHub**）：
   - `npx wrangler secret put RESEND_API_KEY`
   - `npx wrangler secret put EMAIL_FROM`（例：`NELUUN <login@你的已驗證寄件網域>`）
   - `npx wrangler secret put OTP_PEPPER`（長度至少 32 字元的隨機字串）
   - `npx wrangler secret put SESSION_PEPPER`（與 OTP_PEPPER 不同，至少 32 字元）
5. `npm run deploy`。務必先用測試帳號完成寄信、驗證碼、登入、登出等測試。
6. **AI 預設關閉**。只有在已設定 OpenAI 專案預算及後端安全、費用與隱私要求後，才執行 `npx wrangler secret put OPENAI_API_KEY`，並於 `wrangler.jsonc` 中將 `AI_ENABLED` 設為 `"true"` 後重新部署。即使個人助理 AI 開啟，兒童 AI 仍固定關閉。

Cloudflare Workers static assets 參考： https://developers.cloudflare.com/workers/static-assets/binding/
D1 migrations 參考： https://developers.cloudflare.com/d1/wrangler-commands/

## 本機測試

- 本機無後端測試：`cd public && python3 -m http.server 8080`。在瀏覽器開 `http://localhost:8080`，可操作 V8 延續的功能，但「登入」會顯示未連線。
- 程式結構與安全門檻檢查：`npm test`。
- SQL 遷移可在 SQLite 中先驗證；D1 遠端遷移須連線 Cloudflare。

## 隱私與架構備註

- 本機資料沿用 key `neluun_v8_local`，避免使用者資料因升級而消失。**登入並不會把待辦或筆記同步到雲端。**
- 在共用裝置上，別人可能讀到本機保存的內容；可從 App 裡匯出與清除。
- D1 僅儲存登入電子郵件、驗證碼雜湊及過期資訊、session 雜湊與到期、家長自行聲明紀錄、每日 AI 使用計數。當 AI 正式啟用時，個人助理提交的單則訊息會傳送給 AI 供應商，但 Worker 不在 D1 保存正文。
- 本版登入只驗證 **電子郵件控制權**，不會驗證成年或合法監護關係。
- 對外開放前應補充隱私政策、服務條款、刪除雲端帳號資料的正式程序、反濫用防護、監控告警、費用限制，並做完整安全審查。
