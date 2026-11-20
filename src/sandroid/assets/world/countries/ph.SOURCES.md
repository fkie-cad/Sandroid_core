# ph.yaml sources

Pack: Philippines (`countries/ph.yaml`), schema v1. Compiled 2026-11-20 by agent countries-3 (PH fork).

## Sources

| ID | Source | Accessed | Licence | Used for |
|----|--------|----------|---------|----------|
| S1 | Wikipedia, "Telephone numbers in the Philippines", https://en.wikipedia.org/wiki/Telephone_numbers_in_the_Philippines | 2026-11-20 | CC BY-SA 4.0 (only facts taken) | 10-digit mobile NSN, 8-digit Metro Manila landlines since 2019, area codes, DITO 0895-0898 / 0991-0994 |
| S2 | Twilio / PLDT notices on the Metro Manila 8-digit migration (https://www.twilio.com/en-us/blog/change-philippines-local-numbering-plan, https://pldthome.com/updateto8) | 2026-11-20 | facts | Landline subscriber length, operator first digit |
| S3 | Google libphonenumber via Python `phonenumbers` 9.0.43 (PyPI), PH metadata and carrier data | 2026-11-20 | Apache-2.0 | Prefix-to-operator mapping, validity tests of all realistic/unallocated prefixes, landline formats |
| S4 | FilipiKnow, "An Ultimate Guide to Mobile Number Prefixes in the Philippines", https://filipiknow.net/list-of-mobile-number-prefixes/ | 2026-11-20 | facts only (cross-check, nothing copied) | Cross-check of prefix assignments; source of the disputed 0904/0913/0940/0941 entries |
| S5 | GitHub 0xbitx/PH_Mobile_Number_Prefixes, https://github.com/0xbitx/PH_Mobile_Number_Prefixes | 2026-11-20 | no licence stated, so used as a cross-check only | Cross-check; confirms 0900-0904, 0980, 0982, 0984, 0990 are in no list |
| S6 | Web searches for NTC allocation tables and PH fiction ranges (ntc.gov.ph, FOI portal request "criteria-format-of-valid-mobile-phone-numbers", which returned HTTP 403) | 2026-11-20 | n/a | Negative result: no public NTC block table and no fiction range |
| S7 | PSA 2020 Census of Population and Housing: city populations, religion (Islam 6.4%), ethnicity (foreign ethnicity 230,917, of which Chinese 102,577), foreign citizens 78,396 (India 24.2%, US 8.0%). psa.gov.ph releases, also cited via Wikipedia and Philstar (2023-02-22) | 2026-11-20 | Philippine government statistics, facts | `cities.population`, `cultures` shares |
| S8 | PSA most-common baby names (2017 infographic; 2020-2024 lists as tabulated at https://www.behindthename.com/top/lists/philippines/2024, which credits the PSA) | 2026-11-20 | facts (ranks only) | Youngest cohort of the given-name pools (Nathaniel, Jayden, Ezekiel, Althea, Samantha, Princess...) |
| S9 | Publicly reported surname rankings (Baguio City Guide, "Top 1000 Filipino Last Names", which reproduces about 2014 Forebears figures: dela Cruz 1, Garcia 2, Reyes 3, Ramos 4, Mendoza 5, Santos 6, Flores 7) | 2026-11-20 | rank facts only; no list copied | Ordering of the top surname tiers |
| S10 | Google Play Store detail pages, `https://play.google.com/store/apps/details?id=<pkg>&hl=en&gl=PH`, fetched one at a time | 2026-11-20 | facts (package id and title) | All 40 `popular_apps` verified as live, title matches |
| S11 | Wikipedia/OSM coordinates for cities and public landmarks | 2026-11-20 | facts; ODbL for OSM-derived coordinates (attribution: OpenStreetMap contributors) | `cities` lat/lon, `places` |
| S12 | RA 9492 (holiday economics law) and annual Malacañang holiday proclamations | 2026-11-20 | public law, facts | `holidays` |
| S13 | Carrier/brand shares: Globe and PLDT/Smart 2024-25 public subscriber reports, DITO disclosures | 2026-11-20 | facts, rounded estimates | `carriers.share` |

## Authored (hand-written / AI-drafted, not from a dataset)

- **Name pools** (`names.female`, `names.male`, `names.surnames`): curated by hand. No Faker PH person provider exists (Faker ships only en_PH/fil_PH address, bank and other providers), so Faker was not used. Weights are hand-assigned tiers (1.0 / 0.8 / 0.6 / 0.4; surnames 1.0 down to 0.15). They are anchored on S8 (young cohort) and S9 (top-surname order). The older cohorts (Teresita, Corazon, Rodolfo, Danilo...) and the 1980s-90s cohort (Mary Grace, John Paul, Mark Anthony, Jessa, Jomar...) come from general knowledge. Generator script: scratchpad `data/countries-3/ph/names.py`.
- **Nicknames, display conventions, middle-name rule**: authored (general cultural knowledge).
- **Streets**: authored list of nationally recurring street names (heroes, saints, flowers, native trees). Not copied from any dataset.
- **Postcodes and districts**: well-known PHLPost ZIPs and barangay/district names (facts).
- **Services sender IDs**: authored from common knowledge of PH SMS inboxes. Exact casing and spelling per brand is not verified against telco sender-ID registries, which are not public (e.g. "SecBank", "SPX", "PAGIBIG"). The Globe 8080 and Smart 9999 short codes are well-known promo-registration codes.
- **Email domain shares**: authored estimates.
- **Language shares** (fil 0.55 / en 0.30 / ceb 0.15): authored estimate. Cebuano speakers are about 20% of the population (PSA 2020 household language), discounted because many Bisaya write Taglish or English in SMS.
- **Place coordinates** were entered by hand from S11 and rounded to about 4 decimals. Treat them as approximate (within about 100-300 m).

## Excluded / notes

- **Digido** (`com.finora.application` is titled "DIGIDO", but its listing now describes a budgeting tool) and **MoneyCat** (`ph.moneycat` returns "Not Found" on Play PH as of 2026-11-20; appgoblin.info shows a last update in March 2025) are left out of `popular_apps`. The "Digido" SMS sender is kept.
- **Disputed mobile prefixes** (0904, 0913, 0924, 0934, 0940, 0941, 0944) are left out of both `realistic` and `unallocated`.
