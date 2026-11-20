# Sources: countries/nl.yaml

All sources accessed 2026-11-20 unless noted.

| ID | Source | Licence | What was taken |
|----|--------|---------|----------------|
| S1 | Nummerplan (BWBR0010198, in force 2025-10-03), https://wetten.overheid.nl/BWBR0010198 | law (facts) | mobile ranges 061-065, 068; no fiction category |
| S2 | ACM nummerregister (operators per block), https://www.acm.nl/sites/default/files/registers/nummers_csv.zip (file dated 2026-11-16) | public register (facts) | `realistic` prefix→operator |
| S3 | same register, gaps between allocated ("Toegekend") rows | facts | `unallocated`: 0632460000-0632999999, 0656270000-0656999999, 0688000000-0688799999 |
| S4 | ACM Telecommonitor Q1 2026, https://www.acm.nl/nl/publicaties/mobiele-markt-ziet-lichte-daling | facts | carrier share bands (KPN 25-30%, Odido 25-30%, VodafoneZiggo 20-25%); normalised to host-network shares |
| S5 | Wikipedia (nl), "Lijst van meest voorkomende achternamen van Nederland" (Meertens/CBG Familienamenbank, 2007 counts) | used as facts | top-100 surnames with counts |
| S6 | CBS StatLine 85458NED "Bevolking; herkomstland" (1 Jan 2026), https://opendata.cbs.nl/statline/#/CBS/nl/dataset/85458NED | facts | `cultures` shares |
| S7 | Wikipedia page coordinates (MediaWiki API) | facts | `places` |
| S8 | Google Play / mirror listing URLs | facts | `popular_apps` package ids |

## Authored / estimated
- **First names**: no openly licensed full frequency file exists (the Meertens Voornamenbank is not openly licensed). Pools are call names (roepnamen) of mixed generations, authored in weight tiers from published SVB / Meertens top-name rankings (facts). Weights are tiers, not counts.
- **Surname supplement** (~90 names after the top 100): authored common Dutch surnames, flat weight at 60% of rank 100.
- Streets, cities (rounded populations; postcode letter suffixes are illustrative, the 4-digit parts are real), email domains, services, nicknames: authored.
- sim_operator strings are commonly observed values, not verified on a device.
- Places: Veluwemeer point moved to Harderwijk shore by hand.

## Validation
`phonenumbers` 9.0.43: every sample in the unallocated gaps is valid MOBILE (carrier lookup is stale for 0656). `fiction: null`: no Dutch fiction range exists. The register lists only allocated rows, so a gap can also be in cool-down or blocked; it is not assigned to any operator.
