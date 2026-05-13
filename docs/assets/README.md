# Visual Identity Assets

This directory holds the visual assets for the Plenith brand:
logo, color palette, typography, and the do/don't usage guide.

**Current status**: pre-launch placeholder. The actual logo file
is creative work that will be commissioned. This README documents
the spec the designer needs to follow.

When the assets land, they replace this README's placeholder
references; the spec below stays as the canonical "how to use
the brand" reference.

---

## Files this directory will contain

| File | Purpose |
| :--- | :--- |
| `logo.svg` | Primary logo, vector, dark-on-light |
| `logo-inverse.svg` | Inverse variant, light-on-dark |
| `logo-mark.svg` | Mark only (no wordmark) — for favicons, social avatars |
| `logo-wordmark.svg` | Wordmark only — for tight horizontal contexts |
| `favicon.ico` | 16/32/48px favicon stack |
| `social-card.png` | OpenGraph image, 1200×630px |
| `colors.txt` | Brand color hex values (canonical source) |
| `type.txt` | Typography stack |

---

## Brand spec

### Concept

Plenith's brand should communicate: **calm, capable, precise**.

It is NOT trying to communicate: aggressive, military, scary,
"hacker culture," or AI-hype. The buyers are SOC professionals and
GRC leads; they want a tool that looks like serious infrastructure.

Reference points (in tone, not literal style):
- HashiCorp's identity (calm, capable, infrastructure-grade)
- Grafana Labs (technical, approachable, no military signaling)
- Tailscale (clean, modern, doesn't try too hard)

What to AVOID:
- Skull / crosshair / lock imagery (overused; reads as 2010s
  security-vendor cliché)
- "Cyber" gradient backgrounds with hex characters scrolling
- AI-generated synthetic art (looks dated quickly + license risk)
- Military / camo / olive-drab palettes

### The mark

The mark is the visual element used standalone (favicon, social
avatar, app icon). It should:

- Be recognizable at 16×16px
- Work in monochrome (a real logo proves itself by surviving
  reduction to a single color)
- Have no fine detail that disappears at small sizes
- Be defensible as a trademark (distinctive, not a common shape)

**Concept direction** (designer's discretion to interpret):
The name "Plenith" was chosen as a brandable container without
inherent meaning. The mark should feel **structural** — a
geometric form suggesting solidity + interlock, not a literal
metaphor for honeypots, deception, or AI.

One direction worth exploring: a stylized **plinth** (the
architectural pedestal — phonetic neighbor of Plenith). A plinth
is structurally honest — it's what holds something up. A SOC
platform is the plinth under the operator's broader security
stack.

Other directions worth NOT exploring:
- Honeypot literal imagery (jars, bees, honey)
- Spider webs
- Carnivorous plants
- Caltrops (separate ADR — that name is gone)
- Mirrors
- Eye-of-providence

### The wordmark

Plain "plenith" in lowercase reads cleaner and more modern than
"Plenith" capitalized. Final choice up to the designer; both
forms should exist in the asset set.

The wordmark is set in a custom or commercial typeface (see
typography below). It should NOT be set in a generic system font
or in a free Google Font that thousands of other projects use.

### Color palette

The palette is **3 + 2**: three brand colors plus two functional
colors used in dashboards / alerts.

#### Brand colors (designer chooses specific hex; constraints below)

- **Primary**: a deep, slightly desaturated blue or green-blue.
  Conveys trust + calm. Sufficient contrast against both pure
  white and pure black. AVOID royal blue / pure cyan
  (overused in security).
- **Secondary**: a warm neutral. Cream, sand, or warm grey.
  Adds organic feel; balances the cool primary.
- **Accent**: one bright, distinctive color used sparingly for
  call-to-action and active states. AVOID red (reserved for alert
  severity below).

#### Functional colors (fixed per the dashboard / alerts)

- **Critical / alert red**: `#d63b3b` (currently in
  `tools/dashboard.py`)
- **High / warn orange**: `#e8851e`
- **Medium / caution yellow**: `#d8b91a`
- **Info / signal teal**: `#3aa6c2`
- **OK / nominal green**: `#3ddc97`

These are the colors operators are conditioned to read in alerts;
changing them is a usability regression. The brand palette must
COEXIST with these without clashing.

### Typography

- **Display + headlines**: a humanist sans-serif with personality.
  Inter, Söhne, Untitled Sans, or a custom face — all acceptable.
  AVOID Helvetica / Roboto (generic) and AVOID anything with
  excessive geometric quirks.
- **Body**: same family as display, lower weight. Optical sizing
  if the family supports it.
- **Monospace** (for code in docs + dashboard): JetBrains Mono,
  IBM Plex Mono, Berkeley Mono, or similar. NOT Courier; NOT a
  pixelated retro font.

### Logo usage rules

DOs:
- Use the SVG variants whenever possible (raster only when SVG
  isn't supported)
- Maintain at least 1× mark-height clear space around the logo
- Use the inverse variant on dark backgrounds; never the
  primary-on-dark unsupported
- Embed the wordmark + mark together when first introducing the
  brand on a page; the mark alone is acceptable for repeat
  references

DON'Ts:
- Don't recolor the logo to match a customer's palette
- Don't stretch, skew, or rotate
- Don't apply drop shadows / outer glows / gradients
- Don't place over photographic backgrounds without a backing
  panel
- Don't reproduce below 16×16px (use a simplified mark instead)
- Don't combine with other words without explicit permission
  ("PlenithLabs", "PlenithGuard", etc. — these are trademark
  violations, see `TRADEMARK.md`)

### Where assets are used

- **GitHub repo** — README header, social-card.png as OG image
- **Project website** — when it exists
- **Dashboard** (`tools/dashboard.py`) — small mark in the
  top-left of the SOC view
- **Slack / Discord / community presence** — channel avatars
- **Conference talks, blog posts** — slide headers
- **Press kit** (when one exists) — high-res versions for media
  pickup

### What the designer needs from us

If you're commissioning the designer:

1. This document (the spec)
2. The MISSION.md (so they understand the tone)
3. The competitive landscape (Acalvio / Illusive / CounterCraft
   visual identities, plus the reference points listed above)
4. Sample dashboards (so the brand palette doesn't clash with
   the functional colors)
5. Three rounds + final delivery in SVG + PNG + ICO formats

### What the designer should deliver

A complete asset bundle:

- All `*.svg` files (vector, optimized)
- Raster PNG versions at @1x, @2x, @3x for each
- Favicon `.ico` with the standard size stack
- The 1200×630 social card
- A 1-page brand-guide PDF summarizing the colors + type +
  do/don'ts (for sharing with future contributors who'll touch
  marketing materials)

Budget guidance: $2,000–$8,000 for a competent independent
designer; $15K+ for a small studio. The mission-driven framing
(`MISSION.md`) may attract designers willing to work at the lower
end of the range.

---

## Pre-launch placeholder

Until the real assets land, the project uses:

- **Placeholder logo**: text "Plenith" set in a system sans-serif
  (whatever the rendering context provides)
- **Placeholder color**: `#1f2937` (the dashboard's neutral dark
  background, already in `tools/dashboard.py`)
- **No favicon** (browsers show the GitHub default)
- **No social card** (link previews show a fallback)

This is intentional — shipping placeholder assets at launch is
worse than no assets, because the placeholders set a quality
floor that's hard to walk back.

---

## Once the real assets land

The PR that adds the asset files should also:

1. Update `README.md` to reference the new logo at the top
2. Update `tools/dashboard.py` to include the mark
3. Update the GitHub repo's Open Graph image
4. Update social profile pictures (Twitter, LinkedIn, etc.)
5. Add a row to `CHANGELOG.md` [Unreleased] mentioning the
   visual identity work
6. Add the brand-guide PDF (or link to it) here

This README itself stays — it remains the canonical spec that
future asset updates have to conform to.

---

*Last updated: 2026-05-12.*
*Companion to [TRADEMARK.md](../../TRADEMARK.md) — that file
covers the LEGAL side of the brand; this directory covers the
VISUAL side.*
