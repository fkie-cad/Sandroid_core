# Sources: `br.yaml` (Brazil)

Generated 2026-11-20 by agent countries-2. Build scripts: scratchpad `data/countries-2/scripts/` (`names_br.py`, `c_br.py`, `build.py`).

| Id | Source | Accessed | Licence | What was taken |
|----|--------|----------|---------|----------------|
| S1 | IBGE *Nomes no Brasil* API, Censo 2010: `https://servicodados.ibge.gov.br/api/v2/censos/nomes/ranking?sexo=F|M&decada=…` and `.../nomes/{nome}?sexo=F|M` | 2026-11-20 | IBGE open data (public, reuse with citation "Fonte: IBGE"); facts | Candidate names = IBGE top-20 per sex and decade (1930-2000s) + Faker pt_BR name lists; each queried for its per-decade frequency. Weight = Σ decade frequency × cohort weight (1950s-1990s ×1, 2000s ×0.6, 1940s ×0.7, older lower). Top 150 female / 137 male kept. |
| S2 | IBGE *Nomes no Brasil*, Censo 2022 surnames (released 2025-11-04), via press coverage e.g. `https://tribunadejundiai.com.br/mais/brasil/sobrenomes-mais-comuns-brasil-ibge-censo-2022/` and `https://www.cnnbrasil.com.br/nacional/brasil/ibge-revela-nomes-e-sobrenomes-mais-populares-do-brasil-veja-ranking/` | 2026-11-20 | facts | Counts of the 11 most common surnames (Silva 34,030,104 … Sousa 4,797,390). No downloadable surname table/API was found (the v3 endpoints tried returned 503/timeouts). |
| S3 | Python `phonenumbers` 9.0.43 BR metadata (Apache-2.0), mirroring Anatel's CN (DDD) plan | 2026-11-20 | Apache-2.0 / facts | The 67 designated two-digit CNs; the 22 undesignated CNs used for `unallocated`. |
| S4 | Faker `pt_BR` person provider (MIT) | 2026-11-20 | MIT | Only as extra candidate names for S1 queries and as the accented spelling of IBGE's unaccented upper-case names (plus a hand-written accent map). No Faker-only names were kept without an IBGE frequency. |
| S5 | Google Play store pages | 2026-11-20 | facts | package existence + title |

## Authored
- Surnames beyond the top 11: rank order from general knowledge, **weights extrapolated** with Zipf(rank^-1.1) from the 11th count. Includes a few immigrant-origin surnames frequent in the South/São Paulo (Schmidt, Müller, Rossi, Ferrari, Yamamoto, Nakamura, Haddad, Salomão) at low weight.
- Cities (IBGE Censo 2022 populations, rounded), state, timezone, CEPs (format-correct codes in each city's range; not checked individually against the Correios database, which is proprietary), bairros, streets, places + coordinates (general knowledge, ~100-500 m), carriers (shares ≈ Anatel 2025 mobile access data, estimate), email domains, service senders (Brazilian A2P SMS uses numeric short codes; entries carry brand names), holidays, nicknames.

## Notes / caveats
- `unallocated` uses **undesignated area codes** (structurally valid 11-digit numbers that can never ring, but INVALID in libphonenumber). Inside designated DDDs no free prefix could be confirmed: Anatel/ABR Telecom publish no downloadable prefix-assignment table, and libphonenumber accepts every 9xxxx-xxxx subscriber number.
- `fiction: null`: Brazil has no official fiction range.
- `cultures: []`. `needs_culture_packs`: jp (Japanese-Brazilians; Censo 2022 "amarela" 0.4 %, ancestry ~1 %), ve (Venezuelans, largest recent immigrant group), ht, bo, py, pt. Italian/German/Lebanese descent is already reflected in Brazilian given names and in a few surnames.
