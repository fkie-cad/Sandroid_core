# Sources: `es.yaml` (Spain)

Generated 2026-11-20 by agent countries-2. Build scripts (reproducible): scratchpad `data/countries-2/scripts/` (`c_es.py`, `names_es_gb_us.py`, `build.py`).

| Id | Source | Accessed | Licence | What was taken |
|----|--------|----------|---------|----------------|
| S1 | INE, *Nombres y apellidos más frecuentes*: `https://www.ine.es/daco/daco42/nombyapel/nombres_por_edad_media.xlsx` and `.../apellidos_frecuencia.xls` (population at 1 Jan 2025) | 2026-11-20 | INE reuse terms (free reuse incl. commercial, with attribution "Fuente: INE"); statistics are facts | Top 150 male and 150 female given names with counts, top 250 first surnames with counts. Weights = count / top count. Accents restored by a hand-written map (INE publishes upper case without accents). Removed: Mohamed, Mohammed, Ahmed, Youssef and the surnames Singh, Chen, Wang, Li, Zhang, Kaur etc. (covered by culture packs / `needs_culture_packs`). |
| S2 | CNMC, *Registro de Numeración* full dump `https://numeracionyoperadores.cnmc.es/bd-num.zip` (file `moviles.txt`, data of 2026-11-19), listed on datos.gob.es as dataset `ea0042931-registro-de-numeracion-de-telecomunicaciones-cnmc` | 2026-11-20 | CNMC legal notice (open data, reuse with attribution); facts | Which 6xx/7xx blocks are assigned and to whom (`realistic`), and which 4-digit blocks in 6xx/71-74/78 are absent from the registry (`unallocated`). Blocks marked "Libre con Portados" (free but containing ported numbers) were excluded. |
| S3 | INE press release *Censo Anual de Población 2025* (foreign nationals at 1 Jan 2025): `https://ine.es/dyngs/Prensa/CensoVariables2025.htm` | 2026-11-20 | INE reuse terms; facts | `cultures` shares = nationals of IT/GB/DE/FR/PK/BR ÷ 49,128,297. |
| S4 | Python `phonenumbers` 9.0.43 (port of Google libphonenumber), Apache-2.0 | 2026-11-20 | Apache-2.0 (tool only, no data copied) | Validity/type checks quoted in `validation_note`. |
| S5 | Google Play store pages `https://play.google.com/store/apps/details?id=<package>` | 2026-11-20 | facts (package id + app title) | Every `popular_apps` package was checked to exist (HTTP 200) and its title matched. |

## Authored (hand-written / AI-written, from general knowledge)
- City list, populations (INE Padrón order of magnitude, rounded), district names, sample postcodes (real postcode ranges of the city, not tied to addresses), landline area codes, street names (typical Spanish *callejero* names), address format, places + coordinates (public landmarks, parks, stations; coordinates from general knowledge, rounded to 4 decimals, accuracy ~100-500 m, area features use a central point), email domains and shares, email patterns, service senders, holidays, carrier shares, nickname map. **Carrier and email shares are estimates**, not official statistics (CNMC publishes line counts per group, not per brand in this exact split).
- `languages`: estimate of text written in Castilian vs Catalan/Valencian, Galician, Basque, English.

## Notes / caveats
- `fiction: null`: Spain has no official drama/fiction range (none in the CNMC plan).
- `unallocated` can become assigned at any time; refresh from S2 before use.
- `needs_culture_packs` (not modelled, no pack in this project), INE 2025 shares: ma 1.97 %, co 1.38 %, ro 1.24 %, ve 0.77 %, pe 0.53 %, cn 0.49 %, ua 0.41 %, hn 0.36 %, ar 0.30 %, ec 0.27 %, py 0.25 %, ru 0.23 %, pt 0.22 %, bg 0.22 %. Latin-American nationals mostly have Spanish-language names, so the `es` pool is a reasonable stand-in.
- Language packs needed for `ca`, `gl`, `eu` if regional text is wanted.
