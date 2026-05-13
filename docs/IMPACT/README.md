# Impact Reports

This directory contains the annual impact reports required by
[`MISSION.md` § "Governance" §1](../../MISSION.md). Each report
covers one calendar year of Plenith's commercial activity and
reports against the 30% children's-development pledge.

The reports live here, in this repository, under the same Apache
2.0 license as the rest of the project. There is no separate
"transparency page" buried in a marketing site. If the
information matters, it sits in version control where the public
can read every revision.

---

## Filing schedule

| Period covered | Report due | Filename |
| :--- | :--- | :--- |
| CY 2026 | 2027-04-01 | `2026.md` |
| CY 2027 | 2028-04-01 | `2027.md` |
| CY 2028 | 2029-04-01 | `2028.md` |
| ... | ... | ... |

The April 1 cadence matches typical US tax-year reporting
requirements and gives the Mission Stewards three months after
calendar year-end to compile, audit, and publish.

---

## What each report must contain

Per the binding commitment in `MISSION.md`, each annual report
includes:

### 1. Financial summary
- **Gross commercial revenue** for the reported year. Itemized by
  offering category (compliance bundles, persona packs, managed
  deployments, subscription products, premium support, training).
- **Direct operating costs** for delivering those offerings.
  Itemized by cost category (labor, infrastructure, third-party
  services, etc.).
- **Net commercial revenue** (gross minus direct operating costs).
- **30% floor calculation**: the dollar amount that 30% of net
  represents.
- **Actual amount allocated** to children's-development
  initiatives. Required to be ≥ the 30% floor; may be higher.

### 2. Allocation detail
- List of recipient organizations + grants for the year.
- For each: the recipient name, the amount, the purpose
  (qualifying under `MISSION.md` § "What 'children's development'
  means"), and the date of the transfer.
- Aggregate redaction is acceptable only if the recipient
  specifically requested anonymity AND the Mission Stewards
  judged the request reasonable. Aggregate amounts must still
  reconcile to the financial total.

### 3. Governance + process
- Names of the Mission Stewards who approved the allocations.
- Notes on any allocation decisions that were contested + how
  resolved.
- Status of the 501(c)(3) sponsor relationship (per `MISSION.md`
  § "Governance" §2 — required before first allocation > $50K).

### 4. Mission compliance check
- Explicit re-affirmation of the open-source-forever promise.
- List of any commercial-offering changes that occurred during the
  year (new offerings, retired offerings, repricing).
- Any deviations from policy + how addressed.
- Status of mission-amendment activity (if any).

### 5. Independent review (when revenue allows)
Starting at gross annual commercial revenue ≥ $500,000, each
report must include either:
- Letter from an independent auditor confirming the report's
  financial figures match the project's books, OR
- Letter from the 501(c)(3) sponsor confirming the allocations
  reached the named recipients.

Below the $500K threshold, the Mission Stewards' signatures are
sufficient.

---

## Reporting template

A template is maintained at `_TEMPLATE.md` in this directory. New
year reports start by copying the template and filling each
section. The template version is bumped only when the reporting
format itself changes (typically to add a new disclosure category).

Once a report is published, it is immutable — corrections happen
via a separate `corrections.md` entry referencing the affected
report, not by rewriting history.

---

## Why this exists

A 30% pledge is easy to state and easy to forget. Procedural
artifacts — annual reports filed by a deadline, in public, with
financial detail and independent signoff — convert the pledge
from intention to commitment.

If a year passes without a report on schedule:

1. The Mission Stewards have failed a procedural duty under
   `GOVERNANCE.md`.
2. Any contributor with ten or more accepted commits may file a
   `mission-amendment` issue requesting cause + remedy.
3. Repeated failures (two consecutive years) trigger the
   "Removing a Mission Steward" procedure in `GOVERNANCE.md`.

The seriousness of the consequences reflects the seriousness of
the commitment. We can never argue this isn't a real obligation —
the documentation says it is, the procedural locks say it is, and
the public can see every report (or its absence).

---

## What this directory does NOT contain

- Marketing material about the impact
- Press releases
- Photographs of recipients (privacy)
- Tax forms (those live in the maintainer-org's accounting system,
  separate from public reporting)
- Commercial pricing detail (that goes on the project website)

This is a financial + procedural disclosure directory, not a
public-relations channel.

---

*Last updated: 2026-05-12.*
*First report due: 2027-04-01 (covering CY 2026).*
