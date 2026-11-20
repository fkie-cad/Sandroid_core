# Sources: countries/id.yaml (Indonesia)

All accessed 2026-11-20 by agent countries-3 (fork for ID). Only facts were taken (prefix lists, counts, codes, coordinates, package ids); no text was copied.

| ID | Source | Licence / status | What was taken |
|----|--------|------------------|----------------|
| S1 | Permenkominfo No. 14/2018, Rencana Dasar Teknis (FTP) Telekomunikasi Nasional, https://peraturan.bpk.go.id/Download/141810/Permen%20Kominfo%20Nomor%2014%20Tahun%202018.pdf | Indonesian regulation (public law, facts) | Mobile NDC structure (08XY, X != 0,6; 086X, X != 1), subscriber length set by operators, 0800-0809 IN services and "belum dialokasikan" 0801-0803/0805, no fiction range |
| S2 | en.wikipedia "Telephone numbers in Indonesia" | CC BY-SA 4.0 (facts only) | operator prefix lists, area codes, 7/8-digit landline rule |
| S3 | id.wikipedia "Nomor telepon di Indonesia" (raw wikitext, prefix table and area-code list) | CC BY-SA 4.0 (facts only) | per-prefix operator assignment incl. vacant 0825/0827/0828/0829 and 0868 (PSN satellite); absence of 0820, 0824, 0826, 0834-0836, 0854, 0871, 0874, 0891, 0893 from every operator; mobile length 10-13 digits incl. 0 |
| S4 | Google libphonenumber via `phonenumbers` 9.0.43 (pip, local venv) | Apache-2.0 | validity/type checks of every prefix and length (see validation_note) |
| S5 | Web search for an Indonesian drama/fiction number range (none found) | n/a | basis for `fiction: null` |
| S6 | CNBC Indonesia 2025-10-27 "Daftar nama yang paling banyak digunakan di e-KTP" (reporting Dukcapil Kemendagri data) | facts | top-10 female/male given names with counts (weights of the top-10 entries); 2024 baby-name lists |
| S7 | Metrotvnews "Nama paling populer di Indonesia berdasarkan generasi" (Dukcapil data, 2026) | facts | top-3 names per generation (Slamet, Mulyadi, Herman, Wahyudi, Ardiansyah, Aldi, Muhammad Al Fatih, Sri Wahyuni, Siti Aisyah, Fitriani, Ernawati ...) |
| S8 | BPS Sensus Penduduk 2010 ethnicity tables (Chinese-Indonesian 2,832,510 = 1.20%) and en.wikipedia "Indian Indonesians" (~120,000) | facts | `cultures` comment and the `in` share |
| S9 | Wikipedia / OpenStreetMap coordinates of each listed public place and city centre | facts (ODbL for OSM: attribution "© OpenStreetMap contributors") | lat/lon rounded to 4 decimals |
| S10 | Google Play listings, https://play.google.com/store/apps/details?id=<pkg>&gl=ID, checked by HTTP 200 + page title; Play search used to discover Easycash (com.fintopia.idnEasycash.google) and UangMe | facts | every `popular_apps` package id |
| S11 | BPS Sensus Penduduk 2020 city populations | facts | `cities[].population` |
| S12 | Operator annual reports / press 2024-2025 (Telkomsel, Indosat Ooredoo Hutchison, XL Axiata, Smartfren; XLSMART merger 2025) and ITU E.212 MNC list | facts | carrier shares (rounded estimates), MCC-MNC 51010/51001/51089/51011/51008/51009 |
| S13 | OJK list of licensed fintech lenders (as reported, e.g. bisnis.com 2026-11-07 "Daftar pinjol legal OJK") | facts | choice of loan apps (AdaKami, Easycash, Kredit Pintar, JULO, Kredivo, Akulaku, Indodana, UangMe all OJK-licensed) |
| S14 | Faker `id_ID` person provider (MIT), local venv | MIT | consulted only as a cross-check for surname/given-name coverage; no list copied wholesale |

## Authored (hand-written / AI-drafted, marked "authored")
- Weights of all name entries beyond the Dukcapil top-10 per sex (estimates on the same scale, mixing generations).
- Surname pool composition (patronymic-like second names + Batak, Minahasa, Maluku, Chinese-Indonesian, Arab-Indonesian, Balinese family names); Batak share kept near the ~3.6% Batak population (BPS 2010).
- Nicknames, display conventions, street list (common national-hero and flower/fruit street names, facts of common usage), email shares and patterns.
- SMS sender IDs: assembled from common knowledge of masked sender names used by Indonesian operators/brands; exact casing varies per operator and over time (authored, not verified per sender).
- City postcodes: representative codes inside each city's Pos Indonesia block (format and block are facts; individual district-code pairing not verified).
- Landline subscriber lengths: rule of thumb from S2/S3 (8 digits in Jakarta, 7 in other 2-digit-code metros, mostly 6 elsewhere), checked against S4.
- Language shares and time/date format conventions.

## Not used / gaps
- RupiahCepat Play package could not be found/verified: omitted.
- No regulator-published per-operator NDC allocation table could be retrieved (S1 delegates allocation to the Director General; Komdigi/SDPPI pages did not expose a list). `unallocated` therefore rests on S3 (medium confidence).
- Name frequency beyond top-10 per sex is not published by Dukcapil as open data.
