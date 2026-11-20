# Sources: `gb.yaml` (United Kingdom)

Generated 2026-11-20 by agent countries-2. Build scripts: scratchpad `data/countries-2/scripts/` (`c_gb.py`, `names_es_gb_us.py`, `build.py`).

| Id | Source | Accessed | Licence | What was taken |
|----|--------|----------|---------|----------------|
| S1 | R package `ukbabynames` 0.3.0 (CRAN, `https://cran.r-project.org/package=ukbabynames`), which repackages ONS baby names for England & Wales 1996-2020, the GRO/ONS historic top-100 lists 1904-1994 and National Records of Scotland 1974-2020 | 2026-11-20 | Package CC0; underlying data Open Government Licence v3.0 (attribution: "Contains public sector information licensed under the OGL v3.0", ONS / NRS) | Given-name pools. Weight = blend of cohorts (1944-1994 decade top-100 ranks converted with a Zipf approximation, 1996-2020 counts), E&W 92 % / Scotland 8 %, weighted toward adults living today. Mohammed/Muhammad/Mohammad and a few other names were dropped because they are modelled through the `pk`/`in` cultures. |
| S2 | Ofcom, *Numbers for drama* `https://www.ofcom.org.uk/phones-and-broadband/phone-numbers/numbers-for-drama` (read via search snippet; the site blocks automated fetching) cross-checked with `github.com/neilzone/ofcom_drama_range_phone_number_generator/index.php` | 2026-11-20 | facts | `mobile.fiction` (07700 900000-900999) and all `landline.fiction` ranges (13 geographic + 01632, 0808 157, 0909 879, 0306 999). |
| S3 | Python `phonenumbers` 9.0.43 GB metadata (Apache-2.0) | 2026-11-20 | Apache-2.0 (facts derived) | `unallocated`: the only 5-digit 07[1-9] blocks libphonenumber rejects (077002/4/5/6, 079113/4/5/6). Ofcom's own S7.csv (Free/Allocated per block) could **not** be downloaded (Cloudflare challenge), so these are not confirmed against Ofcom. |
| S4 | ONS, *International migration, England and Wales: Census 2021* `https://www.ons.gov.uk/peoplepopulationandcommunity/populationandmigration/internationalmigration/bulletins/internationalmigrationenglandandwales/census2021` | 2026-11-20 | OGL v3.0 | Country-of-birth counts: Italy 277k, United States 203k (÷ 59.6M). Nigeria and Germany appear in the top-10 list without a figure on that page; their shares (0.45 %, 0.2 %, the latter discounted because many German-born are children of British service families) are estimates. |
| S5 | ONS, *Ethnic group, England and Wales: Census 2021* `https://www.ons.gov.uk/peoplepopulationandcommunity/culturalidentity/ethnicity/bulletins/ethnicgroupenglandandwales/census2021` | not re-fetched (published figures) | OGL v3.0 | Indian 3.1 %, Pakistani 2.7 % → `cultures` in/pk (ethnic group, so UK-born second generation is included). |
| S6 | Google Play store pages | 2026-11-20 | facts | Existence + title of every `popular_apps` package. |

## Authored
- Surname list: rank order of the most common surnames in Great Britain from general knowledge (ONS 2002 rank lists as widely reported); **weights are synthetic Zipf(rank^-0.85), not counts** (no open official surname-frequency file exists). Patel, Khan, Singh, Ali, Hussain, Begum, Ahmed, Shah, Kaur were excluded (culture packs).
- Cities, populations (rounded local-authority figures), districts, outward postcodes, area codes and subscriber lengths, streets, places + coordinates (general knowledge, ~100-500 m accuracy), carriers + shares (estimates; MVNO brands mapped to host-network MCC-MNC), email domains/shares/patterns, service senders, holidays, nicknames.

## Notes / caveats
- `postcodes` are outward codes only (e.g. `SW11`): full postcodes identify ~15 delivery points and Royal Mail PAF is proprietary. The generator should append a random inward code (`{digit}{letter}{letter}`). The schema has no field for this (see report).
- Mobile `realistic.operator` is null: UK prefixes do not identify the network.
- Holidays use an extended rule syntax `MM-dow#n` (n=-1 = last), e.g. `05-mon#-1`.
- `needs_culture_packs`: pl (Poland-born 1.2 %), ro (0.9 %), ie (0.55 %), bd (Bangladeshi 1.1 %), cn (Chinese 0.7 %), jm / Caribbean (1.0 %), za.
- `cy` (Welsh) language pack needed for the 1 % Welsh text share.
