# Sources: `tr.yaml` (Türkiye)

Generated 2026-11-20 by agent countries-2. Build scripts: scratchpad `data/countries-2/scripts/` (`c_tr.py`, `build.py`).

| Id | Source | Accessed | Licence | What was taken |
|----|--------|----------|---------|----------------|
| S2 | BTK, *Numara Yönetim Sistemi Numaralandırma Raporu (Kamuya Açık)* `https://www.btk.gov.tr/s3/web-btk-site/uploads/ntsfiles/NPR.pdf` (report date 18/11/2026), linked from `https://btk.gov.tr/en/numbers-allocated-to-operators` | 2026-11-20 | public regulator report (facts) | All 4-digit MN (mobile) blocks and their holders → `realistic` (TT Mobil 501, 505-507, 551-555, 559; Turkcell 530-539 + 56161; Vodafone 540-549); 3-digit 5XX codes with no MN allocation → `unallocated` (502, 503, 504, 508, 509, 556, 557, 558). |
| S3 | Python `phonenumbers` 9.0.43 | 2026-11-20 | Apache-2.0 | All `unallocated` prefixes are **valid MOBILE** in libphonenumber (its TR pattern is broader than BTK's allocations). |
| S4 | Google Play store pages | 2026-11-20 | facts | package existence + title |

## Authored
- **Name pools are authored**, not downloaded: TÜİK publishes only top-10 lists in press bulletins and no open frequency file was retrievable. Order follows the well-known TÜİK rankings (female: Fatma, Ayşe, Emine, Hatice, Zeynep …; male: Mehmet, Mustafa, Ahmet, Ali, Hüseyin …; surnames: Yılmaz, Kaya, Demir, Çelik, Şahin, Yıldız, Yıldırım, Öztürk, Aydın, Özdemir …) and continues with common older and younger-generation names. **Weights are synthetic Zipf(rank^-0.95/-0.9).** Faker tr_TR was inspected but not used (its lists are rare names and include politically loaded surnames).
- Cities (TÜİK ADNKS 2024 province populations, rounded), districts, postcodes (plausible 5-digit codes in each province's range, not verified per district), streets, places + coordinates (general knowledge), carriers (shares ≈ BTK quarterly market data, estimate), email domains, senders (Turkish SMS headers are upper-case brand names), holidays, nicknames.
- Holidays: Ramazan/Kurban Bayramı use an extended rule `hijri:MM-DD`.

## Notes / caveats
- `fiction: null`: no official fiction/drama range is known for Türkiye.
- `cultures: []` — no minority with a pack in this project is large enough. `needs_culture_packs`: ku (Kurds, est. 15-20 % of the population; most carry Turkish-style names, Kurdish given names such as Rojda, Berfin, Welat are common in the south-east), sy (Syrians under temporary protection, ~2.5-3 % in 2025), af, iq, ir, az, ru, ua.
- Language packs: `ku` and `ar` shares are small; text is overwhelmingly Turkish.
