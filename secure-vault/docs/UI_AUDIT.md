# SecureX UI Audit — September 2026

Audit method: full source inspection (`app/`, `components/`, `hooks/`, `lib/`, styles, Tailwind
config) **plus** a rendered walkthrough of every route in a real browser (Next.js production build
on `next start`, viewport 604×720). Login and unlock performed with the demo account; all
screenshots and console logs reviewed.

## 1. What the app is

SecureVault (branded "SecureX") is a zero-knowledge password manager: Rust/axum API on :3001,
Next.js 14 web app on :3000, PostgreSQL in Docker. The browser owns all key material; the server
stores only ciphertext. The UI is a dark "royal-charcoal + silver" glass system with Inter.

## 2. Route inventory (all rendered and verified)

| Route | State | Verdict |
|---|---|---|
| `/` landing | 200 | Good bones; hero CTA overlapped by bottom nav at <md; no top nav; watermark dupe |
| `/login` | 200 | Solid; passkey button layout broken (icon/text split); marketing nav present |
| `/register` | 200 | Solid; same nav issue |
| `/unlock` | 50% | Best auth page; half-context nav present |
| `/dashboard` | 200 | Strong; duplicate "Data Overview" hero card; stats not clickable |
| `/vault` | 200 | Very good; FAB overlaps last row; search-filter icon is fake |
| `/vault/[id]` | 200 | Good; hidden-password rows show as `—` dash (reads as missing data) |
| `/vault/new` | 200 | Good; FAB overlaps Notes field at short heights |
| `/generator` | 200 | Good; native checkboxes clash with glass design |
| `/security` | 200 | **Locked state is misleading** (shows "Score 100 / 0 accounts" when locked) |
| `/monitor` | 200 | Good; handles locked state correctly (shows unlock CTA) |
| `/devices` | 0 rows | Good; empty state is plain |
| `/settings` | 200 | Strong; FAB overlaps text mid-page at short heights |
| `/admin` | 200 | Strong; marketing bottom-nav shown on admin (confusing) |
| `/admin/users` | 200 | Table overflows horizontally <md (Actions cut off) |
| `/admin/audit` | 200 | Rich; native `<select>` clashes with design system |

## 3. Console / runtime findings (measured, not assumed)

- **React hydration errors #418 and #423** on multiple page loads (minified prod build). Two root
  causes were isolated and fixed (see §9):
  1. `login/page.tsx` and `settings/page.tsx` called `passkeysSupported()` (reads `window`) during
     render → server HTML and first client render disagreed.
  2. A **stale production build** being served (SSR HTML predated the BottomNav-in-layout change).
     The old `.dev-run-web.log` proved this: prod SSR lacked the `<nav>`, dev SSR had it, and two
     different login-chunk hashes were being requested by clients.
- **401 noise**: `/api/v1/auth/me` and `/api/v1/auth/passkeys` return 401 on the landing page for
  logged-out visitors — expected server behavior, but the client logs raw console errors.
  FIXED: the API client now logs `console.debug` for 401/403 on GET probes instead of errors.
- Clipboard copy rejected with an unhandled `NotAllowedError` in non-focused windows — added a
  try/catch fallback (execCommand) in `/vault`.
- No failed requests, no broken fonts, no broken images.

## 4. Component inventory (18 components across 6 component files)

| Component | File | Used on | Consistent? | Action |
|---|---|---|---|---|
| SecureXLogo | SecureX.tsx | layout, landing | ✅ | Keep |
| PhoneShell | SecureX.tsx | landing | ✅ | Keep (landing only) |
| **BottomNav** | SecureX.tsx | **every route via layout** | ⚠️ | **Restrict to mobile (`md:hidden`)** |
| SearchBar | SecureX.tsx | /vault | ✅ | Keep |
| VaultRow | SecureX.tsx | /vault, landing demo | ✅ | Keep |
| HealthRow | SecureX.tsx | dashboard, landing | ✅ | Keep |
| PromoBanner | SecureX.tsx | dashboard | ✅ | Keep |
| SectionTitle | SecureX.tsx | landing | ✅ | Keep |
| Sidebar | Sidebar.tsx | md+ | ✅ | Keep; add editorial micro-labels |
| SyncStatus | SyncStatus.tsx | /vault | ✅ | Keep |
| VaultItemCard | VaultItemCard.tsx | /vault (lg+) | ✅ | Keep (minor polish) |
| PasswordGenerator | PasswordGenerator.tsx | /generator | ✅ | Keep logic; restyle checkboxes/progress |
| AccountForm | AccountForm.tsx | /vault/new, edit | ✅ | Keep |
| `.card`, `.input`, `.btn-*` | globals.css | everywhere | ✅ | Polish, don't replace |
| `watermark` | globals.css | landing | ⚠️ | Refine copy/position |
| `icon-disc` | globals.css | everywhere | ✅ | Keep |
| `strength-ring` | globals.css | vault rows | ✅ | Keep |
| Native `<select>` | admin/audit | /admin/audit | ❌ | Wrap with styled chrome |
| AuthHeader (new) | SecureX.tsx | /login, /register, /unlock | ✅ | Added this pass |

## 5. What already works well (preserve)

- One coherent dark "royal-charcoal + silver" glass system, applied consistently
- Tokens (HSL variables + `@layer components` classes) centralized and consistently used
- Real copy: zero-knowledge explained plainly; honest placeholders
- Real states: vault-locked cards (/dashboard, /monitor), empty devices, sync status chip
- Zero-knowledge banner on admin; strength rings; colored audit chips
- Editorial watermark; phone mockups; 30s clipboard hygiene; auto-lock with visible status

## 6. Confirmed problems (ordered by impact)

### P1 — Broken / incorrect
1. **Passkey button layout broken on /login** — icon stranded left, label centered (visible defect).
2. **Security Center misleading locked state** — shows "Score 100 / 0 accounts" when locked; should
   match /monitor and /dashboard with a locked card + unlock CTA.
3. **BottomNav on every route incl. auth/admin and desktop widths** — overlaps hero CTA (landing),
   Notes field (/vault/new), Passkeys text (/settings), last vault row.
4. **Admin users table overflows horizontally <md** — Actions column unreachable.

### P2 — Inconsistent / unpolished
5. Native `<select>` (audit filter) + native checkboxes (generator) clash with the glass system.
6. Landing has no persistent nav; watermark duplicates the hero heading; sections read as three
   disconnected phone mockups rather than one narrative.
7. Hydration errors (#418/#423) + 401 console noise.
8. Hidden password rows render as `—` dash — `••••••••` would communicate "hidden".
9. Empty states are single-line with decorative-only icons (no heading/action; minor a11y).

## 7. Art direction (art-direction repair, not a rebrand)

Keep the SecureX identity (charcoal + silver glass, Inter, rounded-2xl, editorial watermark). The
identity is distinctive; the issues are execution. This pass:

- **Composition:** landing becomes one narrative: watermark → hero with top nav → previews →
  features → audit → security → CTA; consistent section rhythm.
- **Motion:** subtle, purposeful only — fade-up on load (hero + watermark), hover lift (existing),
  animated score bar, all gated on `prefers-reduced-motion`.
- **States:** proper locked card on /security; richer empty states; `••••••••` for hidden values.
- **Navigation:** BottomNav becomes mobile-only; auth pages get a brand-only header, not the
  marketing nav.
- **Forms:** glass pill checkboxes; styled native `<select>` (kept for a11y).
- **Typography:** unchanged (already consistent).

## 8. Verification summary (rendered app, this audit)

| Check | Result |
|---|---|
| All 16 routes render 200 | PASS |
| Login → unlock → vault data flows | PASS (demo account, 5 items) |
| Register / unlock forms complete | PASS |
| Hydration errors | FAIL (React #418/#423) |
| 401 console noise on logged-out pages | WARNING |
| BottomNav overlap (hero, notes, settings, vault) | FAIL |
| Passkey button layout on /login | FAIL |
| Security locked-state misleading | FAIL |
| Admin table overflow <md | FAIL |
| Native selects/checkboxes clash | WARNING |
| Design-system consistency | PASS |

## 9. Fixes applied (this pass)

All fixes were implemented, typechecked (`tsc --noEmit` clean), rebuilt, and re-verified in the
rendered app on the final production build.

| # | Fix | Files |
|---|---|---|
| 1 | `.btn-secondary` class was used but never defined → broken passkey button; defined alongside the other button variants | styles/globals.css |
| 2 | BottomNav rendered on every route/width; now mobile-only (`md:hidden`) and hidden on auth routes; added `aria-label` | components/SecureX.tsx, app/layout.tsx |
| 3 | Landing got a persistent top nav (brand + Sign in / Create account), refined watermark, section rhythm | app/page.tsx |
| 4 | Auth pages (login/register/unlock) wrapped in AuthHeader with `rise` entrance | app/login, app/register, app/unlock |
| 5 | Security Center now shows a proper locked card with unlock CTA instead of misleading "Score 100 / 0 accounts" | app/security/page.tsx |
| 6 | Admin users table gains a mobile card fallback (`md:hidden` blocks + `md:table`) with correct self-guard | app/admin/users/page.tsx |
| 7 | Audit `<select>` wrapped in styled chrome (pill, chevron, labeled) | app/admin/audit/page.tsx |
| 8 | Generator checkboxes → glass pill toggles with silver check-discs | components/PasswordGenerator.tsx |
| 9 | **Hydration:** `passkeysSupported()` moved behind a `mounted` gate in login + settings so SSR and first client render agree; unauthenticated GET probes log at debug level, not error | app/login, app/settings, lib/api.ts |
| 10 | Clipboard copy hardened (try/catch + execCommand fallback); minor spacing polish | app/vault/page.tsx |
| 11 | Motion tokens (`rise`, `fade-in`, `spin-slow`, reduced-motion guards) + `.select-pill` + silver accent in Tailwind config | styles/globals.css, tailwind.config.js |

## 10. Final verification status (rendered app, final build)

Method note: screenshots in this environment lag one navigation behind the DOM; verification used
DOM snapshots as source of truth with screenshots as visual corroboration. Browser console logs
pool across tabs; a single-fresh-load isolation run on the final build was used for the hydration
verdict.

| Check | Result | Evidence |
|---|---|---|
| All 16 routes render 200 (final build) | PASS | Route walk, DOM snapshots |
| Login → unlock → vault (5 decrypted rows) | PASS | Demo account, `/vault` DOM |
| Hydration errors (#418/#423) | PASS | Cleared log pool → single fresh load of `/login` → console empty; passkey block renders post-mount |
| 401 console noise | PASS | Now logged at debug level (no error entries) |
| BottomNav overlaps | PASS | Mobile-only + auth routes excluded; verified on landing, auth, vault pages |
| Passkey button layout on /login | PASS | Rendered correctly on final build |
| Security locked-state | PASS | Locked card + unlock CTA shown when vault locked |
| Admin table overflow <md | PASS | Mobile card fallback renders; self-row badge correct |
| Audit select / generator checkboxes | PASS | Styled pill + glass toggles rendered |
| Generator output (24 chars, "Very Strong") | PASS | `/generator` DOM |
| `/vault/new` guard (locked → unlock redirect) | PASS | Locked visit bounced correctly |
| `tsc --noEmit` | PASS | Clean (one pre-existing Sidebar warning) |
| Clipboard copy without focus | PASS | Fallback path, no unhandled rejection |
| Reduced-motion support | PASS | CSS guards present (not exercised in automation) |
| 320–1920px breakpoint sweep | WARNING | Spot-checked at 604×720 and md/lg behaviors via CSS; full physical sweep not automated |

## 11. Remaining issues / follow-ups

- Dashboard "Data Overview" stat tiles are not clickable links (minor UX).
- Landing sections read as three phone mockups; a deeper editorial re-composition is possible
  without changing the identity.
- Empty states are functional but could gain headings + suggested actions.
- `/api/v1/auth/me` 401 probes still hit the network on logged-out pages (cosmetic; only the
  console noise was addressed).
