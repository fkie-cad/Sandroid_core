# Sources: countries/at.yaml

All sources accessed 2026-11-20 unless noted.

| ID | Source | Licence | What was taken |
|----|--------|---------|----------------|
| S1 | Statistik Austria OGD, "Vornamen" OGDEXT_VORNAMEN_1 (newborns 1984-2025 by sex and district), https://data.statistik.gv.at/web/meta.jsp?dataset=OGDEXT_VORNAMEN_1 | CC BY 4.0, attribution "Statistik Austria" | first names with counts; births 1984-2007 weight 1.0, 2008-2025 weight 0.3 |
| S2 | KEM-V 2009 §61 (mobile number format, 3-digit code + 7-10 digits), https://www.jusline.at/gesetz/kem-v_2009/paragraf/61 | law (facts) | NSN length |
| S3 | RTR Open Data, table `tn-dienste` (allocated non-geographic numbers), published 2026-11-19, https://data.rtr.at/api/v1/tables/tn-dienste.json | open data (facts) | `realistic` original holders; codes marked "nicht zugeteilt" → `unallocated` |
| S4 | RTR press release 2026-06-11 (SIM shares end 2025), https://www.rtr.at/TKP/presse/pressemitteilungen/presseinformationen_2026/pinfo11062026tkp.de.html | facts | carrier shares |
| S5 | Wikipedia (de), "Familiennamen in Österreich", section "Die 50 häufigsten Familiennamen Österreichs" (from telephone subscriber data) | used as facts (ranking only) | top-50 surnames, Zipf weights |
| S6 | Statistik Austria, born-abroad by country 1.1.2026 (Bev_Geburtsland_Bundesland_Zeitreihe.ods) and Migrationshintergrund 2025 tables, https://www.statistik.at/fileadmin/pages/407/Bev_Geburtsland_Bundesland_Zeitreihe.ods , https://www.statistik.at/fileadmin/pages/435/Tabellensammlung_Migrationshintergrund_2025.ods | facts | `cultures` shares (tr = migration background incl. 2nd gen 3.3%; de = born in Germany 3.0%) |
| S7 | Wikipedia page coordinates (MediaWiki API) | facts | `places` |
| S8 | Google Play / mirror listing URLs | facts | `popular_apps` package ids |

## Authored / estimated
- **Older-generation first names** (born ~1945-1983, not covered by S1): authored tiers.
- **Surname supplement** (~135 names after the top 50): authored common Austrian surnames (incl. Horvath, Novak, Nowak, Kovacs, which are long-established Austrian names), flat low weight. Faker was not used.
- Streets, cities (rounded populations, sample postcodes/districts), email domains, services, nicknames: authored.
- Carrier sim_operator strings ("A1", "Magenta", "3 AT", "HoT", "spusu") are commonly observed values, not verified on a device. MNC 232-07 for HoT is the code on its host network.
- Places: lake/beach points (Wörthersee/Strandbad, Attersee, Neusiedler See, Wolfgangsee, Traunsee) moved by hand to shore towns.
- Holidays: facts; Karfreitag has not been a public holiday since 2019 (marked `observance`).

## Validation
`phonenumbers` 9.0.43: every unallocated code is valid MOBILE (no carrier). 0659/0669 are unallocated per RTR but libphonenumber labels them "A1", so they were excluded. No fiction range exists (`fiction: null`).
