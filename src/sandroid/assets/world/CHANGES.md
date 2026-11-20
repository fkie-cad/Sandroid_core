# World pack edits (schema v1 to v1.1)

The packs in this directory were copied verbatim from the world_packs data work
(commit "feat(world): ship the world packs in the package (verbatim copy)") and
then changed only at the format level so that they conform to schema v1.1
(`src/sandroid/world/PACK_SCHEMA.md`). No fact was added: every change below
either rewrites a value the pack already stated into the v1.1 form, or turns a
v1 "SCHEMA gap" comment the pack authors wrote into the v1.1 field it asked for.
`git diff` against that commit shows each edit.

## All packs

- `schema: 1` became `schema: 1.1` (17 country packs, 14 language packs, the
  photo manifest). File header comments that still say "schema v1" were left as
  they are.

## photos/manifest.yaml

- `original_exif_stripped` removed from all 150 entries (dropped in v1.1: it was
  ambiguous; `original_had_exif` / `original_had_gps` carry the information).

## countries/es.yaml

- `{sender: WhatsApp, kind: otp_service, sender_type: number}` became
  `{sender: "+34...", label: WhatsApp, kind: otp_service, sender_type: number}`:
  a `number` sender must be a number pattern; the brand moved to the v1.1 `label`.
  `"+34..."` only says "a Spanish number", the least specific valid pattern.

## countries/fr.yaml

- 126 surnames were wrapped in leftover wiki markup, `'{{page h|Lambert}}'`;
  the markup was removed (`Lambert`). The validator now rejects markup
  characters in names.

## countries/ke.yaml

The pack filed these senders under the closest v1 kind and named the intended
kind in its section comments ("proposed kind: ...").

- `kind: bank` became `kind: mobile_money`: MPESA, M-SHWARI, AIRTELMONEY, T-KASH.
- `kind: bank` became `kind: lender`: Tala, Branch, Zenka, ZashLoan, M-KOPA,
  Watu, and the `"+254 7..."` number sender of the lender section.
- `kind: retail` became `kind: betting`: BETIKA, SPORTPESA.
- Holiday added from the holidays comment ("Eid al-Fitr is a public holiday but
  follows the lunar calendar ... proposed rule"): `{rule: "hijri:10-01", name:
  Eid al-Fitr}`.

## countries/id.yaml

- `kind: bank` became `kind: mobile_money`: DANA, OVO, GoPay, ShopeePay
  (section "e-wallets (mobile money) [kind bank: SCHEMA gap]").
- `kind: bank` became `kind: lender`: Kredivo, Akulaku, AdaKami, Easycash,
  KreditPintar, JULO and the two collection numbers `"+62857..."`,
  `"+62831..."` (section "lenders / paylater (pinjol) [kind bank: SCHEMA gap]").
- The eight commented-out holiday proposals became entries. The five
  `hijri:` rules are unchanged; the other-calendar ones use the v1.1
  `lunisolar:` form: `chinese:01-01` became `lunisolar:chinese_new_year`,
  `saka:nyepi` became `lunisolar:nyepi`, `buddhist:vesak` became
  `lunisolar:vesak` (the generator skips `lunisolar:` dates).

## countries/ph.yaml

- `kind: bank` became `kind: mobile_money`: GCash, Maya, PalawanPay, Cebuana,
  MLhuillier, Coins.ph (section "E-wallets / mobile money").
- `kind: bank` became `kind: lender`: Tala, Cashalo, BillEase, HomeCredit,
  Atome, JuanHand, Digido and the two collection numbers `"+63995..."`,
  `"+63961..."` (section "Lending / BNPL (no `lender` kind in schema ...)").
- `sender_type: number` became `sender_type: shortcode`: `"8080"`, `"9999"`
  (commented as promo short codes).
- The holidays comment "Not expressible in schema: National Heroes Day = last
  Monday of August; Chinese New Year (lunar); Eid'l Fitr and Eid'l Adha" became
  four entries: `08-mon#-1` National Heroes Day,
  `lunisolar:chinese_new_year`, `hijri:10-01` Eid'l Fitr, `hijri:12-10` Eid'l
  Adha (1 Shawwal and 10 Dhu al-Hijja by definition).

## countries/pk.yaml

- `kind: bank` became `kind: mobile_money`: `"8558"` (JazzCash), `"3737"`
  (easypaisa), JazzCash, easypaisa, SadaPay, NayaPay, UPaisa (section "mobile
  money / branchless banking").
- `kind: bank` became `kind: lender`: Paisayaar, SmartQarza, Aitemaad (each
  commented "lender (no `lender` kind in schema v1)").
- `sender_type: number` became `sender_type: shortcode` for the numeric short
  codes the pack comment says were written as `number` without "+": 8558, 3737,
  6222, 8484, 668, 8400, 9966, 8300.
- The nine commented-out `hijri:` holiday rules became entries, unchanged; the
  comment that called the syntax "PROPOSED" now names it the v1.1 syntax.

## countries/ng.yaml

- `kind: bank` became `kind: mobile_money`: OPay, PalmPay, Moniepoint, Kuda,
  MoMoPSB (section "Mobile money / fintech wallets").
- `kind: bank` became `kind: lender`: FairMoney, Carbon, Branch, PalmCredit,
  Renmoney, Aella, QuickCheck, OKash (section "Digital lenders").
- `sender_type: number` became `sender_type: shortcode`: `"131"` (commented
  "MTN info/service short code").
- Holidays named in the holidays comment ("Eid al-Fitr 2 days, Eid al-Adha 2
  days, Eid-el-Maulud ... proposed rule form hijri:10-01") became entries:
  `hijri:10-01`, `hijri:10-02`, `hijri:12-10`, `hijri:12-11`, `hijri:03-12`.

## Not changed (content gaps, reported by the validator as warnings)

- Number levels that are `null` (no fiction range, no known unallocated block).
- Languages and cultures a country names without a pack (`ca`, `cy`, `jv`,
  `so`, `ph-moro`, ...).
- `shortcode` senders without a numeric code (br, us).
- `us` names carry `g` tags without `names.groups` shares.
- Thread counts below the recommended 15 per relationship.
- 14 photos marked `has_people: true` (the generator does not pick them).
- Proposals that would need new judgement rather than a format change were left
  in their comments: `id` mononym share (age-dependent), `ke`/`id`/`ph`
  display variants (no weights given), `ng` name groups (no tags given), `ke`
  Sunday-to-Monday holiday shifts.
