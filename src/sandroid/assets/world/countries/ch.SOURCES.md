# Sources: countries/ch.yaml

All sources accessed 2026-11-20 unless noted.

| ID | Source | Licence | What was taken |
|----|--------|---------|----------------|
| S1 | BFS, "Weibliche Vornamen der Bevölkerung nach Jahrgang, Schweiz, 2022", https://dam-api.bfs.admin.ch/hub/api/dam/assets/26925127/master | opendata.swiss BFS terms: open use, source must be cited ("Source: BFS"); commercial use needs permission | female first names, all residents born 1945-2006, counts |
| S2 | BFS, "Männliche Vornamen der Bevölkerung nach Jahrgang, Schweiz, 2022", https://dam-api.bfs.admin.ch/hub/api/dam/assets/26925126/master | as S1 | male first names, same method |
| S3 | BFS, "Nachnamen der ständigen Wohnbevölkerung nach Sprachregion" 2024, https://dam-api.bfs.admin.ch/hub/api/dam/assets/36062364/master | as S1 | surnames summed over all language regions |
| S4 | BAKOM numbering plan SR 784.101.113/2.2, ed. 8 (in force 2024-03-01), https://www.bakom.admin.ch/dam/en/sd-web/Z0P7gateTOUQ/TAV_PTA_2_2_ed8_e%20(1).pdf | law (facts) | mobile codes 07x, NSN 9 digits |
| S5 | 20 Minuten, 2021, BAKOM advice on numbers in films, https://www.20min.ch/story/in-der-schweiz-koennte-squid-game-nummern-problem-auch-auftreten-652118478228 | facts | no official fiction range; use undiallable numbers |
| S6 | ComCom market shares (BAKOM data, end 2024), https://www.comcom.admin.ch/en/market-share | facts | carrier shares |
| S7 | BFS SAKE 2024 migration status by citizenship, https://dam-api.bfs.admin.ch/hub/api/dam/assets/36187248/master ; BFS language statistics (main languages) | facts | `cultures` shares; `languages` split |
| S8 | Wikipedia page coordinates (MediaWiki API) | facts | `places` |
| S9 | Google Play / mirror listing URLs | facts | `popular_apps` package ids |

**Licence note:** BFS files carry a "commercial use requires permission" clause. Only name frequency rankings (facts, explicitly allowed by the brief) were taken, with the source cited. If Sandroid is distributed commercially, re-check BFS terms or switch to the Stadt Zürich CC0 name data.

## Processing
- Names of the Portuguese/Spanish, Kosovar/Albanian, Arab, Turkish and Vietnamese diaspora (e.g. da Silva, Krasniqi, Nguyen, José, Mohamed) were removed from the majority pool so they come in through `cultures`. Italian names were kept (national language; Ticino).
- Mobile `realistic` operator mapping comes from libphonenumber's carrier data and Wikipedia, NOT from BAKOM (unverified; portability applies).

## Authored / estimated
- Streets (German, French and Italian), cities (rounded populations), email domains, services, nicknames: authored.
- Places hand-entered: Castelgrande (Bellinzona; the Wikipedia lookup returned a homonym in Italy). Lake/beach points moved by hand to shore spots.
- Holidays: facts; most are cantonal (`regional: true`).

## Gaps
- `mobile.unallocated: null`: BAKOM's allocation list is only an interactive search (egov.swiss) without download; not queried.
- `fiction: null`: no official range exists.
- Swiss German SMS are written in dialect; a `gsw`/`de-CH` language pack would be more realistic than `de`.
