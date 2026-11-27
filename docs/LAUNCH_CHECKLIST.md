# NELUUN launch checklist

Status legend: [x] done, [~] in progress, [ ] not started. Updated 2026-11-27.
Legal items are engineering notes, not legal advice; have a lawyer review before release.

## 1. Auth and family flow (backend)
- [x] Adult and child Workers on separate origins; no cross-login
- [x] Email OTP login (adult)
- [x] TOTP second factor + 8 recovery codes (guardian-aware gating)
- [x] Guardian declaration, child profiles, 8-digit entry code (single use, 10 min), session cap 60 min
- [x] End companion session revokes child session immediately
- [x] OTP_PEPPER consistency check (family.html system check)
- [x] Rate limits on OTP, TOTP, child entry
- [~] Verified sending domain (neluun.app on Resend, status Pending) then set secret EMAIL_FROM
- [ ] Test with a second real email account (non-owner)
- [ ] Account deletion (adult): delete user, children, sessions, TOTP, declarations
- [ ] Child profile deletion with data purge (profile deletion exists; verify cascade of sessions and learning records)
- [ ] Session/inactivity timeout review; logout-everywhere
- [ ] Server-side audit log for guardian actions (declare, start/end companion, TOTP remove)
- [ ] Backup and restore plan for D1; migrations applied via CI, not manually
- [ ] Separate production D1 from test D1; production secrets regenerated (new OTP_PEPPER, SESSION_PEPPER)

## 2. Domains and hosting
- [x] Domain neluun.app registered (Cloudflare Registrar, auto-renew on)
- [ ] Custom domains: adult site and child site (for example app.neluun.app, kids.neluun.app)
- [ ] Update ADULT_ORIGIN / allowed origins, CORS for /api/kids/health, cookie scope check
- [ ] Public static site on neluun.app: privacy policy, terms, support contact, account deletion page
- [ ] Support mailbox (for example support@neluun.app) via email routing
- [ ] Registrant email verified (ICANN) and renewal reminders

## 3. Client packaging
- [ ] Decide delivery: PWA only, or native wrapper (see decision notes)
- [ ] Android: Capacitor/TWA wrapper, signing key in CI secrets, Play Console app, internal then closed testing (12 testers / 14 days if personal account)
- [ ] iOS: wrapper build via cloud Mac CI, App Store Connect record, TestFlight
- [ ] Child app vs adult app split decision (two apps, or one app with parental gate)
- [ ] App icons, splash, screenshots, store listings (zh-Hant, en)
- [ ] Offline behavior and error states
- [ ] Deep links / universal links if native

## 4. Children's privacy and store policy
- [ ] Privacy policy (public URL), written for child data: what is collected, why, retention, deletion, parent rights
- [ ] Terms of service
- [ ] Parental consent flow reviewed against: Taiwan PDPA, COPPA (US), GDPR Art. 8 (EU), UK Children's Code if distributed there
- [ ] Apple: Kids Category rules (no third-party ads/analytics, parental gate for external links and purchases), privacy nutrition labels, age rating questionnaire
- [ ] Google Play: Families Policy, Data safety form, target audience and content declaration, account deletion URL
- [ ] No tracking SDKs in child app; confirm no analytics cookies on child origin
- [ ] Data minimization review (child nickname + avatar only; no real names, no email)
- [ ] Data retention schedule (entry codes, sessions, learning records)
- [ ] Legal review by qualified lawyer

## 5. Learning content
- [ ] Question bank: source, license, and vendor agreement
- [ ] Remove or gate legacy local "parent record" data paths
- [ ] Learning records stored server-side per child (optional) with parent view in family.html
- [ ] Content review for age appropriateness

## 6. AI features (currently OFF for child)
- [ ] Vendor selection (adult and child separately)
- [ ] Gateway: API key server-side only, per-user and global spend caps, request logging policy
- [ ] Child AI: input/output safety filtering, topic limits, no personal data in prompts, parent opt-in, session-bound
- [ ] Prompt-injection and abuse testing
- [ ] Disclosure text in app and privacy policy
- [ ] Kill switch (env flag) verified

## 7. Payments (if any)
- [ ] Decide model (free, one-time, subscription)
- [ ] Store in-app purchase integration; parental gate on purchase screens for child-facing UI
- [ ] Refund and receipt handling

## 8. Quality and operations
- [x] Unit tests (72 passing) and CI syntax checks
- [ ] End-to-end test script (adult login, TOTP, child code, logout, isolation)
- [ ] Real-device matrix: iPhone, Android phone, Samsung tablet, Safari/Chrome
- [ ] Accessibility pass (contrast, font size, screen reader labels)
- [ ] Monitoring and alerts (Worker errors, email send failures, D1 size)
- [ ] Incident process and contact for security reports
- [ ] Load and abuse test of rate limits

## 9. Release
- [ ] Production environment cut-over checklist
- [ ] Store submission: metadata, review notes with test accounts and parent flow walkthrough
- [ ] Staged rollout and rollback plan
