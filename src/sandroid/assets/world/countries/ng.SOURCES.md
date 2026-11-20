# Sources: countries/ng.yaml (Nigeria)

Compiled 2026-11-20 by agent countries-3 (fork NG). All URLs accessed 2026-11-20.

| ID | Source | Licence / status | What was taken |
|----|--------|------------------|----------------|
| S1 | NCC, "Mobile Number Allocation Table" (as at December 2023, page updated 2024-11-25), https://ncc.gov.ng/operators/mobile-number-allocation-table | Government facts | Prefix to operator mapping; 0819 "Withdrawn"/"Available"; 0709 "Withdrawn"; 0702 split blocks; 0700/0800 VAS; 0900 vanity. Basis for `mobile.realistic` and `mobile.unallocated`. |
| S2 | NCC, "Notification to ITU of Existing Mobile ITU-T E.164 Numbers in NNP", https://ncc.gov.ng/media/1062/view (PDF) | Government facts | List of mobile NDCs in service: 701-706, 708, 801-818, 901-909, 911-916 (no 707/709/819/910/917-919). Confirms 10-digit NSN. |
| S3 | NCC, "Notification to ITU of New ITU-T E.164 Numbers in NNP" (Jan 2024), https://ncc.gov.ng/media/1063/view (PDF) | Government facts | 71X and 72X notified as MVNO NDCs, so they were kept out of `unallocated`. |
| S4 | NCC National Numbering page, https://ncc.gov.ng/technology/standards/numbering | Government facts | Index of numbering documents. No fiction/drama range found in any of them, so `fiction: null`. |
| S5 | Nairametrics, "NCC announces change in fixed lines numbering format" (2023-09-20), https://nairametrics.com/2023/09/20/ncc-announces-change-in-fixed-lines-numbering-format/ ; cross-checked with libphonenumber | Facts | Fixed lines became 10-digit with "02" + old area code (Lagos 0201, Ibadan 0202, Abuja 0209). |
| S6 | NCC subscriber data, Dec 2025, as reported by ThisDay / Guardian NG (e.g. https://www.thisdaylive.com/2025/11/27/telecoms-subscriber-base-maintains-steady-growth-rate-hits-173m-with-teledensity-of-80-05) | Facts | Market shares MTN 51.9%, Airtel 33.9%, Glo 12.4%, T2 (ex-9mobile) 1.8%. MCC-MNC codes (621-30/20/50/60) are ITU E.212 facts. |
| S7 | UN World Urbanization Prospects / citypopulation.de style metro estimates | Facts | Approximate city populations, used as weights only. City-centre coordinates are general knowledge, rounded to 4 decimals. |
| S8 | Wikipedia, "Postal codes in Nigeria", https://en.wikipedia.org/wiki/Postal_codes_in_Nigeria | CC BY-SA (facts only) | Legacy postcodes 100001 (Lagos/Ikeja), 900001 (Abuja), 500001 (Port Harcourt), 400001 (Enugu), 460001 (Imo/Owerri). Also: NDAPS 11-character codes replaced 6-digit codes on 2026-10-01. |
| S9 | Wikidata P625 coordinates via the API (https://www.wikidata.org/w/api.php) and Wikipedia `prop=coordinates` | CC0 (Wikidata) | Coordinates of every entry in `places`. |
| S10 | CIA World Factbook, Nigeria, ethnic groups (2018 est.) | Public domain (US Gov) | Hausa 30%, Yoruba 15.5%, Igbo 15.2%, Fulani 6%, Tiv 2.4%, Kanuri 2.4%, Ibibio 1.8%, Ijaw 1.8%. Used only to set the rough name-weight blend. |
| S11 | UN DESA International Migrant Stock 2020, as cited in Vatican M&R "2023 Country Profile Nigeria", https://migrants-refugees.va/wp-content/uploads/2023/08/2023-CP-Nigeria.pdf | Facts | 1,308,568 migrants (0.63%); Benin 377,169, Ghana 238,284, Mali 172,481, Togo 158,262. Converted to shares of a ~206M population. |
| S12 | Public Holidays Act (as amended); Democracy Day moved to 12 June in 2019 | Facts | Fixed-date and Easter-based federal holidays. |
| S13 | Google Play store pages `https://play.google.com/store/apps/details?id=<pkg>&hl=en&gl=ng`, checked with HTTP requests on 2026-11-20 | Facts (package ids and titles only) | All 40 `popular_apps` returned HTTP 200 with the listed title. Candidate ids that 404'd (e.g. `com.accessbank.accessmore`, `com.uba.ubamobile`, `com.palmcredit.loan`) were replaced by the ids found through Play search. The NINAuth listing names NIMC as the publisher. |
| L1 | Google libphonenumber via `phonenumbers` 9.0.43 (Apache-2.0) | Tool | Validity and type of every prefix (see `validation_note`). |
| F1 | Faker 40.54.0 (MIT): `en_NG`, `yo_NG`, `ig_NG`, `ha_NG` person providers | MIT | Used only as a drafting aid and cross-check for the name pools. |

## Authored content (not from a source)

- **Name pools and weights** (`names.female`, `names.male`, `names.surnames`, `nicknames`) were authored from general knowledge of Nigerian naming, with F1 as a drafting aid. No official name-frequency statistics exist for Nigeria, so the weights are rough relative frequencies, not measured ones.
- **Contact-saving conventions** (the comment in `names`) are authored.
- **Street list** was authored. These are real, commonly occurring street names, used with no house numbers.
- **City districts** are general knowledge.
- **SMS sender IDs** (`services`) were authored from common knowledge of Nigerian bank, fintech, telco and agency alerts. They were not individually verified against live SMS. Most uncertain: `MoMoPSB`, `NRC`, `Kwik`, `IKEDC`/`EKEDC`/`AEDC` exact spelling, and `131`.
- **Email domain shares** and **language shares** are authored estimates. No public dataset was found.
- **Diaspora shares below 0.02%** (Lebanese, Chinese, Indian) were omitted for lack of official counts.

## Gaps

- No verifiable coordinates for rail stations, so there are no `station` places.
- Islamic public holidays cannot be expressed in schema v1 (Hijri calendar).
- 0910: medium confidence that it is unallocated. libphonenumber already treats it as mobile.
