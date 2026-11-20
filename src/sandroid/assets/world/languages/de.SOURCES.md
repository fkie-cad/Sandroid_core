# Sources: languages/de.yaml

| Section | Origin | Licence |
|---|---|---|
| threads, service_sms, calendar, files, notes, call_names | **authored** (AI-written by Claude for Sandroid, 2026-11-20). No external text copied; no web sources used. | Authored for this project, no third-party material |

## Conventions

- Register: `du` within family, partner, friends and between colleagues (the usual German office norm); neighbours mix `Sie` (first contact about a parcel) and `du`. Services use `Sie`, except food delivery and one app OTP template, which use `du` as many German apps really do.
- Texting habits modelled: lowercase starts, missing final punctuation, `vllt` (vielleicht), `n` (ein/einen), `aufm` (auf dem), `ca` without dot, `hdl` / `hdgdl` (hab dich (ganz doll) lieb), `lol`, `Jap`, `Ne`, double `!!`/`??`, stretched words (`Dankeee`, `Jaa`).
- Emoji: about 40% of threads. `emoji: true` is set on the thread when at least one message contains emoji (schema v1 has no per-message flag, since messages are `[speaker, text]`). Service SMS contain no emoji.
- Region: neutral standard German usable for DE/AT/CH. CH texts would use `ss` for `ß`; AT users might say `Jänner`; not modelled.
- `{first}` always means the other person in the thread; third parties are hard-coded names (Lena, Tim, Sabine).
- Service SMS mimic real German formats (mTAN, Packstation-style pickup codes, `*100#` balance codes, Abschlag/Zählerstand from utilities) without brand names; the sender name comes from the country pack. `*100#`/`*106#` are generic USSD-style examples, not tied to one operator.
- File names: `{date}` is used (German date `dd.MM.yyyy` is filename-safe); umlauts appear both as `ü` and transliterated `ae`/`ue`, as on real devices.
- File kinds vocabulary (not fixed by the schema): invoice, contract, payslip, statement, tax, cv, ticket, insurance, letter, form, manual, receipt, scan, other.
- `call_names` adds keys `grandma`, `grandpa`, `partner` beyond the schema example's `mom`/`dad`.

## Placeholders used

`{owner_first}`, `{first}`, `{partner_first}`, `{place}`, `{city}`, `{time}`, `{day}`, `{date}`, `{amount}`, `{digits:N}`, `{code}`, `{tracking}`, `{shop}`, `{bank}`, `{courier}`; `{last}` only in file names (as in the schema example).
