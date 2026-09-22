# SecureX Design System

The single visual language for the SecureVault web client ("SecureX"). Every page shares these
tokens and rules; pages may vary composition, never identity.

Identity in one line: **royal-charcoal depth, silver light, glass surfaces, editorial typography.**

---

## 1. Color tokens

Defined as HSL CSS variables in `styles/globals.css` and mapped through `tailwind.config.js`.

| Token | HSL | Usage |
|---|---|---|
| `--background` | `222 34% 6%` | Page base (royal charcoal) |
| `--foreground` | `210 25% 96%` | Primary text (silver white) |
| `--card` | `222 30% 9%` | Card/surface base |
| `--card-foreground` | `210 25% 96%` | Text on surfaces |
| `--muted` | `220 18% 14%` | Muted fills, wells |
| `--muted-foreground` | `218 12% 62%` | Secondary text |
| `--border` | `218 20% 16%` | Hairlines, dividers |
| `--input` | `218 20% 16%` | Input borders |
| `--primary` | `210 20% 96%` | Primary actions (silver) |
| `--primary-foreground` | `222 34% 8%` | Text on primary |
| `--accent` | `43 65% 62%` | Silver-gold accent — highlights, active states, focus, key data |
| `--destructive` | `0 62% 48%` | Destructive actions, errors |
| `--ring` | `43 65% 62%` | Focus rings |

Rules:

- **Gradients are structural, never decorative.** Only the fixed background wash
  (`#0a0e18 → #101526 → #0d1220` radial glows) and the subtle silver sheen on primary buttons.
- **Accent (`43 65% 62%`) is purposeful:** active nav item, focus ring, strength indicators,
  key metrics. Never large fills.
- Status colors come from semantic classes (`text-emerald-*`, `text-amber-*`, `text-rose-*`)
  with glass-chip backgrounds — see §6.

## 2. Typography

- **Family:** Inter (`next/font`), weights 400–800.
- **Display:** tight tracking (`-0.03em`), semibold–extrabold, used for page titles and the hero.
- **Body:** 15–16px, `--muted-foreground` for secondary copy.
- **Micro-labels:** 11–12px uppercase, `tracking-[0.2em]`, muted — used for eyebrows, table heads,
  metadata ("ZERO-KNOWLEDGE", "ALL RIGHTS RESERVED").
- Scale: 12 / 13 / 14 / 15 / 16 / 20 / 24 / 30 / 36 / 48. One jump per hierarchy step.
- Never introduce a second family; never center long body text.

## 3. Spacing & radius

- Spacing rhythm: 4-point grid. Page gutters `px-5 sm:px-8`; section gaps `space-y-8/12`;
  card padding `p-5/6`.
- Radius scale (Tailwind config): `card` 1.25rem, `pill` 9999px, everything else Tailwind defaults.
- Radii within a component must match: if the card is `rounded-card`, its buttons are `rounded-xl`
  and chips are `rounded-pill`.

## 4. Surfaces

Five intentional levels — no ad-hoc surface inventions:

| Level | Class | Look |
|---|---|---|
| Background | fixed gradient layer | charcoal wash + faint glows |
| Surface | `.card` | glass (9% white, 16px blur, hairline border) |
| Elevated | `.card` + `hover:shadow-glass hover:-translate-y-0.5` | interactive lift |
| Interactive | `.input`, `.btn-*`, `.select-pill` | inset hairline, focus ring in accent |
| Overlay | `.icon-disc`, chips | 8% tint fills, 1px borders |

Rules: borders and contrast before shadows; shadows only on hover/interactive elevation;
blur ≤ 16px; one elevation change per interaction.

## 5. Buttons (closed set — no other variants may be invented)

| Class | Purpose |
|---|---|
| `.btn-primary` | One per view. Silver fill, dark text, sheen, hover lift |
| `.btn-secondary` | Glass outline for equal-weight actions (e.g. passkey sign-in) |
| `.btn-ghost` | Tertiary/inline actions |
| `.btn-danger` | Destructive only (sign-out, revoke, delete) |

All: `h-11`, `px-5/6`, `rounded-xl`, `text-sm font-semibold`, `transition`, visible focus ring,
disabled at 50% opacity. Icon + label are centered together — never split.

## 6. Forms

- Inputs: `.input` — `h-11`, glass fill, hairline border, accent focus ring, error state in rose.
- Labels above inputs, 13px, medium weight. Helper text below, 12px, muted.
- Checkboxes/toggles: glass pill with silver check-disc (see `PasswordGenerator`) — native
  appearance is always replaced.
- Selects: native `<select>` kept for a11y, wrapped in `.select-pill` (pill chrome + chevron).
- Never stack more than one primary action per form.

## 7. Navigation

- **Desktop (md+):** `Sidebar` — fixed, brand, icon+label items, accent active state, footer meta.
- **Mobile (<md):** `BottomNav` — floating glass dock, 5 items max, `md:hidden`.
- **Auth pages:** `AuthHeader` (brand + tagline) only. No marketing nav, no dock.
- **Landing:** persistent top nav (brand + Sign in / Create account CTAs).
- Rule: a route shows exactly one navigation surface for its context.

## 8. Motion

Tokens in `tailwind.config.js`; all gated by `prefers-reduced-motion: reduce` in globals.css.

| Token | Use |
|---|---|
| `rise 0.5s ease-out` | Page/hero entrance (translateY 8px → 0, fade) |
| `fade-in 0.4s ease-out` | Secondary content entrance |
| `spin-slow` | Ambient loading only |
| `transition` (default 150ms) | Hover lift, color, opacity |

Rules: motion communicates state and hierarchy only — no perpetual animation, no parallax, no
particles, no layout-shifting animation. One entrance choreography per page.

## 9. States

- **Locked vault:** dedicated locked card (icon, explanation, unlock CTA) — never fake data
  (no "Score 100 / 0 accounts").
- **Empty:** contextual icon + one-line explanation; headings/suggested actions are the known
  next step (see UI_AUDIT §11).
- **Loading:** skeletons/spin-slow chips; never blocking overlays.
- **Error:** inline rose text near the field/action + toast where appropriate.
- Hidden secrets render as `••••••••`, never `—`.

## 10. Icons & imagery

- One system: inline SVG, 1.5px stroke, 16/20/24px, `currentColor`. No mixed icon families.
- App icons sit in `.icon-disc` containers for consistent optical weight.
- Media (phone mockups) is compositional: consistent aspect, same frame treatment, alt text.

## 11. Responsive

- Breakpoints: Tailwind defaults (sm 640 / md 768 / lg 1024 / xl 1280).
- Composition changes at `md`, not just width: tables → card fallbacks (admin users), dock ↔
  sidebar, grid → stack.
- Touch targets ≥ 40px; the mobile dock adds bottom padding to page content so nothing sits
  underneath it.

## 12. Accessibility

- Semantic landmarks (`header/main/nav`), labeled forms, `aria-label` on icon-only controls,
  visible focus rings everywhere (`--ring`), contrast ≥ 4.5:1 for text, reduced-motion honored,
  native `<select>`/`<input>` semantics preserved.

## 13. Visual effects policy

Allowed: background gradient wash, glass blur ≤ 16px, one watermark per page, hover lift,
entrance rise, sheen on primary buttons.

Not allowed: neon, particles, 3D, per-component random gradients, glassmorphism on text-heavy
surfaces, motion that blocks interaction or shifts layout.
