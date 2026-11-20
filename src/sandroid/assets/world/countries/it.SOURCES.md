# Sources: countries/it.yaml

All sources accessed 2026-11-20 unless noted.

| ID | Source | Licence | What was taken |
|----|--------|---------|----------------|
| S1 | AGCOM Piano di numerazione 8/15/CIR, Allegato A art. 8, https://www.agcom.it/sites/default/files/migration/attachment/Allegato%2020-2-2015.pdf | official (facts) | mobile 3XY structure, 30x reserved, NSN 10; no fiction range |
| S2 | MIMIT "File_assegnati_2.xlsx" (assigned numbering, updated 2026-09-15), https://www.mimit.gov.it/images/stories/digitale/numerazione/File_assegnati_2.xlsx | official (facts) | `realistic` prefix→operator |
| S3 | same file: 3XY codes with no assignee | facts | `unallocated` |
| S4 | AGCOM Osservatorio sulle comunicazioni n. 2/2026 (human SIMs, March 2026), https://www.agcom.it/sites/default/files/documenti/osservatorio/AGCOM_Osservatorio%20n.2-2026_0.pdf | facts | carrier shares |
| S5 | Wikipedia (it), "Cognomi italiani" (top-50 national list after MappaDeiCognomi; regional and provincial top-10 tables after italia.indettaglio.it) | used as facts | surnames: top 50 Zipf-weighted, others weighted by how often they appear in regional/provincial top-10s |
| S6 | ISTAT foreign residents by citizenship 1.1.2025 via ISMU, https://www.ismu.org/wp-content/uploads/2026/02/31-Rapporto-ISMU_Slide_Ortensi.pdf ; ISTAT Indicatori demografici 2024 | facts | `cultures` shares (foreign citizens only; undercounts naturalised people) |
| S7 | Legge 8 ottobre 2025 n. 151 (4 ottobre San Francesco festa nazionale from 2026), https://www.normattiva.it/eli/id/2025/10/10/25G00153/CONSOLIDATED/ | law | holiday 10-04 |
| S8 | Wikipedia page coordinates (MediaWiki API) | facts | `places` |
| S9 | Google Play / mirror listing URLs | facts | `popular_apps` package ids |

## Authored / estimated
- **First names**: ISTAT publishes newborn rankings only from 1999 and no downloadable resident-population file was found. Pools are authored in weight tiers from published ISTAT rankings (most common names of residents and of newborns), mixing generations. Weights are tiers, not counts.
- Streets: authored from the commonly cited most frequent Italian odonyms (Via Roma, Via Garibaldi, Via Marconi, Via Mazzini, ...).
- Cities (rounded populations, sample CAP/districts), email domains, services, nicknames: authored.
- sim_operator strings are commonly observed values, not verified on a device.
- Places hand-entered: Parco Sempione, Villa Comunale (Napoli), Mercato di Ballarò. Lake/beach points moved to shore towns.

## Validation
`phonenumbers` 9.0.43: all listed unallocated 3XY codes are valid MOBILE (30x was excluded because libphonenumber rejects it). Italy has no trunk prefix (`trunk_prefix: ""`): landline area codes keep the leading 0 inside the NSN. `fiction: null`.
