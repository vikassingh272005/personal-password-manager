# UI Sources

Record of external design references consulted for the SecureX redesign and how (or whether) they
entered the codebase. **No third-party component code was copied into this project.** All
implemented patterns are owned in `apps/web` (hand-written JSX + Tailwind + `globals.css`), so
there is no license exposure from vendored code.

| # | Source | URL | What was consulted | License | Implementation method | Modifications |
|---|---|---|---|---|---|---|
| 1 | shadcn/ui | https://ui.shadcn.com/ | Design-token naming (HSL CSS variables mapped in Tailwind), component-variant discipline | MIT | Ideas only — no code | Token names already matched the project; no changes needed |
| 2 | Aceternity UI | https://ui.aceternity.com/ | Editorial hero/watermark composition principles | MIT (attribution) | Ideas only — no code | Watermark refined in owned CSS (position, copy); no vendor code |
| 3 | magicui.design | https://magicui.design/ | Entrance-motion restraint (short, purposeful reveals) | MIT | Ideas only — no code | Owned `rise`/`fade-in` keyframes written from scratch |
| 4 | motion.dev | https://motion.dev/ | Motion principles reference (easing, duration, reduced-motion) | MIT (library) | Not installed — CSS keyframes sufficient | n/a |
| 5 | Tremor | https://www.tremor.so/ | Stat-tile hierarchy on dashboards | Apache-2.0 | Ideas only — no code | Existing owned stat tiles kept |
| 6 | cuicui.day | https://cuicui.day/application-ui | Application-shell patterns (nav contexts) | MIT | Ideas only — no code | BottomNav mobile-only + AuthHeader rules are owned code |
| 7 | HyperUI | https://www.hyperui.dev/ | Mobile card fallbacks for wide tables | MIT | Ideas only — no code | Admin users mobile fallback hand-written to match glass system |
| 8 | React Bits | https://www.reactbits.dev/ | Scan for reusable motion primitives | MIT | Nothing adopted | n/a — avoided to keep zero new dependencies |

## Dependencies added

**None.** The entire redesign was implemented with the existing stack (Next.js 14, Tailwind,
hand-written CSS components). No packages were installed or removed.

## Policy

References are for pattern extraction only; the project must not become a mixture of component
libraries. Before any future external component is copied, record here: source URL, license,
what was taken, and the modifications made — and prefer re-implementation in the project's own
tokens (as done above).
