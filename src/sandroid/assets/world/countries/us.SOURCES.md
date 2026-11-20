# Sources: `us.yaml` (United States)

Generated 2026-11-20 by agent countries-2. Build scripts: scratchpad `data/countries-2/scripts/` (`c_us.py`, `us_nxx.py`, `names_es_gb_us.py`, `build.py`).

| Id | Source | Accessed | Licence | What was taken |
|----|--------|----------|---------|----------------|
| S1 | Social Security Administration national baby-name counts 1880-2017, via `github.com/hadley/babynames` (`data/babynames.rda`) (ssa.gov blocked the direct download) | 2026-11-20 | US government work, public domain; package CC0 | 180 female / 180 male names, weight = births 1945-2012 (1945-54 ×0.6, 2005-12 ×0.7 to approximate today's adult contacts). |
| S2 | NANPA Central Office Code Assignment Records: `https://reports.nanpa.com/public/CoCodeAssignment_Utilized_AllStates_Public.zip` and the 8 regional `CoCodeAssignment_Available_*.zip` files (both dated 11/19/2026), linked from `https://nanpa.com/reports/co-code-reports/cocodes_assign` | 2026-11-20 | public numbering-administration data (facts) | `realistic`: NPA-NXX codes in service and held by Cellco (Verizon), New Cingular (AT&T) or T-Mobile/Omnipoint/Sprint Spectrum, 2 per carrier per NPA, seeded random sample. `unallocated`: 3 NXX codes per city from the *available* list of an overlay NPA, excluding N11, 555, 950, 958, 959, 976 and anything libphonenumber rejects. |
| S3 | US Census Bureau, 2010 surnames file `https://www2.census.gov/topics/genealogy/2010surnames/names.zip` | 2026-11-20 | public domain | Top 300 surnames with counts; `g: [hispanic|asian|black]` tag when the Census race/ethnicity share is ≥50 % Hispanic, ≥50 % API or ≥40 % Black. Patel, Singh, Shah, Kumar removed (→ `in` culture). |
| S4 | NANPA fictitious-number reservation 555-0100…555-0199 (NANPA/ATIS INC guidance, widely documented) | 2026-11-20 | facts | `fiction` ranges for each city's first NPA (mobile and landline identical; NANP does not separate them). |
| S5 | Pew Research Center, *Indians in the U.S.* fact sheet (2023 ACS: 4.86 M alone or in combination) `https://www.pewresearch.org/race-ethnicity/fact-sheet/asian-americans-indians-in-the-u-s/`; White House Initiative on AA/NHPI national data fact sheet (2022 ACS PUMS: Filipino 4,436,992, Pakistani 687,942) `https://hhs.gov/sites/default/files/whiaanhpi-aapi-data-national-factsheet.pdf` | 2026-11-20 (search snippets) | facts | `cultures` in 1.45 %, ph 1.32 %, pk 0.21 % (÷ 335 M). ng 0.20 %, br 0.15 %, tr 0.07 %, ke 0.04 %, id 0.04 % are **order-of-magnitude estimates** from ACS ancestry/foreign-born tables not re-fetched here. |
| S6 | Python `phonenumbers` 9.0.43 | 2026-11-20 | Apache-2.0 | validation checks |
| S7 | Google Play store pages | 2026-11-20 | facts | package existence + title |

## Authored
- Hispanic tagging of common given names (`g: [hispanic]` on e.g. Jose, Juan, Maria, Guadalupe) from general knowledge; SSA data has no ethnicity.
- Cities (populations = 2023 Census estimates, rounded), state, timezone, ZIP codes (real ZIPs of the city), neighbourhoods, streets (most common US street names: numbered streets, Main, Oak, Pine …), places + coordinates (general knowledge, ~100-500 m), carriers + shares (estimates; MVNO brands use host MCC-MNC), email domains/shares, holidays.
- SMS senders: US A2P traffic uses short codes. Codes given only where well known (USPS 28777, Amazon 262966, Chase 24273, Bank of America 73981, Wells Fargo 93557, Venmo 86753, PayPal 729725, Google 22000, CVS 287898); other entries carry the brand name and need a generated 5-6 digit short code.

## Notes / caveats
- Unallocated NXX codes are assigned continuously (a few hundred per month nationwide); re-download S2 before relying on them.
- Houston has no `unallocated` entry: its only overlay with spare codes (621) is too new for libphonenumber 9.0.43 and would be rejected by validators.
- `needs_culture_packs`: mx (Mexican origin ~11 %), pr (~1.8 %), cn (~1.6 %), vn (~0.7 %), kr (~0.6 %), sv, do, cu, gt (~0.5-0.8 % each); approximate ACS shares. Hispanic surnames/given names are already in the majority pool (tagged).
