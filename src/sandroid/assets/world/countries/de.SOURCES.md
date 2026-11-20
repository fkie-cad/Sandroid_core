# Sources: countries/de.yaml

All sources accessed 2026-11-20 unless noted.

| ID | Source | Licence | What was taken |
|----|--------|---------|----------------|
| S1 | BNetzA, "Rufnummern für Medienproduktionen (Drama Numbers)", https://www.bundesnetzagentur.de/DE/Fachthemen/Telekommunikation/Nummerierung/DramaNumbers/artikel.html | facts (official list) | all `fiction` ranges: mobile 0171 39200 00-99, 0176 040690 00-99, ten single mobile numbers; landline Berlin 030 23125 xxx, Frankfurt 069 90009 xxx, Hamburg 040 66969 xxx, Köln 0221 4710 xxx, München 089 99998 xxx |
| S2 | BNetzA, "Länge Rufnummernblöcke (Mobile Dienste)", https://www.bundesnetzagentur.de/DE/Fachthemen/Telekommunikation/Nummerierung/MobileDienste/LaengeRNB/start.html | facts | NSN lengths: 015xx = 11, 160/162/163/170-175/177-179 = 10, 176 = 11 |
| S3 | BNetzA, "Freie RNB Mobile Dienste zum 09.03.2022", https://bundesnetzagentur.de/DE/Fachthemen/Telekommunikation/Nummerierung/MobileDienste/freieRNB/start.html | facts | free blocks (0)15-040..099, (0)15-840..879 used as `unallocated` |
| S4 | BNetzA, "Zugeteilte Rufnummernblöcke (Mobile Dienste)", Stand 25.08.2025, https://www.bundesnetzagentur.de/DE/Fachthemen/Telekommunikation/Nummerierung/MobileDienste/zugeteilteRNB/artikel.html | facts | `realistic` prefixes and operators; cross-check that the S3 blocks are still unallocated |
| S5 | BNetzA, "Teilnehmerentwicklung im Mobilfunk" (Q3 2026), https://www.bundesnetzagentur.de/DE/Fachthemen/Telekommunikation/Marktdaten/Mobilfunkteilnehmer/artikel.html | facts | registered SIM counts per network; see note below |
| S6 | Landeshauptstadt München, Open Data "Vornamen von Neugeborenen" 2013 and 2025, https://opendata.muenchen.de/dataset/vornamen-von-neugeborenen | Datenlizenz Deutschland – Namensnennung 2.0 (dl-de/by-2-0). Attribution: "Landeshauptstadt München, Kreisverwaltungsreferat" | younger-generation first names with counts (weight x0.35) |
| S7 | Wikipedia (de), "Liste der häufigsten Familiennamen in Deutschland", rev. of 2026-11-20 | used as facts (ranking only) | the 120 ranked surnames; weights = Zipf(rank^-0.8) because the list has no counts |
| S8 | BAMF Migrationsbericht 2024, Kap. 7, Tab. 7-2 (Destatis Mikrozensus 2024 first results), https://www.bamf.de/SharedDocs/Anlagen/DE/Forschung/Migrationsberichte/MB-2024/migrationsbericht-2024-kap7.pdf | facts | `cultures` shares (people with Einwanderungsgeschichte by origin / 82.77M) |
| S9 | Wikipedia (en/de) page coordinates via MediaWiki API (prop=coordinates) | facts | `places` coordinates |
| S10 | Google Play / AppBrain / APKPure / AppGoblin listing URLs (package id seen in URL) | facts | `popular_apps` package ids |

## Authored / estimated (no external dataset)
- **Older-generation first names** (born ~1945-1995): authored in four weight tiers from the well-known decade rankings (GfdS "beliebteste Vornamen" lists; facts). The weights are tiers, not counts.
- **Surname supplement** (~55 names after rank 120): authored common German surnames, flat low weight.
- **Streets**: authored; order follows commonly cited rankings of the most frequent German street names (Hauptstraße, Schulstraße, Gartenstraße, Bahnhofstraße, ...).
- **Cities**: populations rounded (Destatis 2023 order of magnitude), city-centre coordinates, a sample of real postcodes and district names.
- **Carrier shares**: estimate of human-subscriber shares. BNetzA's registered-SIM counts (S5: Vodafone 101.8M, Telekom 78.7M, Telefónica 35.4M, 1&1 15.0M) are dominated by M2M/IoT SIMs and were not used directly. sim_operator strings are commonly observed values, not verified on a device.
- **Email domains/shares, email patterns, service senders, nicknames**: authored estimates.
- **Places hand-entered**: Clara-Zetkin-Park (Leipzig) — no coordinates in Wikipedia; set by hand. Lake/beach points (Bodensee, Starnberger See, Tegernsee, Warnemünde, Binz) moved by hand from the water centroid to a public shore point.
- **Holidays**: facts. `regional: true` = only in some Länder; `observance: true` = not a public holiday but commonly marked (keys added, see report).

## Validation
`phonenumbers` 9.0.43: all `realistic` and `unallocated` sample numbers parse as valid MOBILE; all `fiction` numbers parse as valid MOBILE/FIXED_LINE. (0)153x/(0)154x are also free at BNetzA but libphonenumber rejects them, so they were left out.
