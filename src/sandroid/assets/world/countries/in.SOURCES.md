# Sources: `in.yaml` (India)

Generated 2026-11-20 by agent countries-2. Build scripts: scratchpad `data/countries-2/scripts/` (`c_in.py`, `build.py`).

| Id | Source | Accessed | Licence | What was taken |
|----|--------|----------|---------|----------------|
| S1 | Census of India 2011, Language (C-16) and Religion (C-1) tables, as widely reported (Hindi 43.6 %, Bengali 8.0 %, Marathi 6.9 %, Telugu 6.7 %, Tamil 5.7 %, Gujarati 4.6 %, Urdu 4.2 %, Kannada 3.6 %, Odia 3.1 %, Malayalam 2.9 %, Punjabi 2.7 %, Assamese 1.3 %; Muslims 14.2 %) | not re-fetched (published facts) | facts | Shares of the name groups (`g`) and of `languages`. |
| S2 | DoT, *Allotment of MSC codes* `https://dot.gov.in/access-services/allotment-msc-codes` (titles of allotment letters, e.g. "Allocation of MSC Code 92430-92439 for Madhya Pradesh LSA" to Reliance Jio, "92230-92239 for Maharashtra LSA") | 2026-11-20 (search snippets) | public government records (facts) | 4 `realistic` entries with operator. |
| S3 | Python `phonenumbers` 9.0.43 IN metadata | 2026-11-20 | Apache-2.0 | `realistic` 3-digit leads chosen only where every following series is MOBILE in libphonenumber (Indian landline numbers share the 10-digit space, e.g. 80-xxxx-xxxx Bengaluru). |
| S4 | Google Play store pages | 2026-11-20 | facts | package existence + title |

## Authored
- **All name pools are authored** (India has no official name-frequency statistics). `names.groups` gives each group's share. Names are grouped by region/community with an optional `g` key: hindi (Hindi belt), marathi, gujarati, bengali, odia_assamese, telugu, tamil, kannada, malayalam, punjabi, muslim (pan-Indian). Within a group, list order = rough popularity; weight = group share × Zipf(rank^-0.9). Names occurring in several groups have their weights summed and list all groups in `g`. Tamil and Telugu naming conventions (initials / father's name or family name as "surname") are reflected in the surname choices. Faker en_IN/hi_IN was inspected but not used.
- Cities (Census 2011 city/UA figures scaled to ~2025, rounded), states, PIN codes (real PINs of central localities), localities, streets (typical "MG Road", "1st Main Road", "100 Feet Road" style), places + coordinates (general knowledge), carriers (shares ≈ TRAI 2025 wireless subscriber data; MCC-MNC differs by circle, one representative given), email domains, holidays.
- SMS senders: DLT-style headers `XY-ABCDEF` (2-letter operator/circle prefix + 6-char sender id). The sender ids are well known (HDFCBK, ICICIB, SBIINB, AXISBK, AMAZON, FLPKRT, IRCTCi-style) but the 2-letter prefixes are illustrative and vary; since 2025 TRAI also appends a type suffix (`-S`, `-T`, `-P`, `-G`).
- Holidays: lunar holidays use extended rules `lunisolar:<name>` and `hijri:MM-DD`; the generator needs a calendar table for these.

## Notes / caveats
- `unallocated: null`: libphonenumber 9.0.43 accepts every series 6000-9999 as mobile, and DoT publishes allotments only as individual PDF letters with no consolidated register of free series. No unallocated block could be stated with confidence.
- `fiction: null`: no official fiction range in India.
- `languages` uses `hi-Latn` for romanized Hindi/Hinglish (common in SMS); a language pack with that tag is assumed. Other language packs needed: bn, mr, te, ta, gu, kn, ml, pa, ur, or.
- `cultures: []`; regional/religious variety is modelled inside the pool via `g`. `needs_culture_packs`: np (Nepalis), bd (Bangladeshis).
