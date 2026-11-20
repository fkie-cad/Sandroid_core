# Sources: countries/pk.yaml (Pakistan)

Compiled 2026-11-20 by agent countries-3 (fork pk). All dates below = date accessed.

| ID | Source | Licence | Used for |
|----|--------|---------|----------|
| S1 | ITU-T, "Pakistan (country code +92)", communication of 9.XI.2021 from PTA, https://www.itu.int/dms_pub/itu-t/oth/02/02/T02020000A10002MSWF.docx (2026-11-20) | facts (ITU national numbering plan publication) | mobile NSN format `3A XXXXXXXX`, A = 0-6; landline NSN lengths (21/42 -> 8-digit SN, other 2-digit NDC -> 7, longer NDC -> 5-6); area codes (NDC list); emergency numbers |
| S2 | Wikipedia, "Telephone numbers in Pakistan", https://en.wikipedia.org/wiki/Telephone_numbers_in_Pakistan (2026-11-20) | facts only (text CC BY-SA, not copied) | 03XZ structure, Zong 0370/0371, landline subscriber lengths cross-check |
| S3 | PTA notice "Mobile numbers changed from 7 to 8 digits" (2008), https://pta.gov.pk/en/media-center/single-media/mobile-numbers-changed-from-7-to-8-digits ; PTA numbering FAQ/forms 2025 (pta.gov.pk refused connections on 2026-11-20, only search snippets seen) | facts | access-code history |
| S4 | Google libphonenumber via Python `phonenumbers` 9.0.43 (Apache-2.0), metadata incl. carrier map, probed locally 2026-11-20 | Apache-2.0 (facts) | operator per 03xx block; validity of unallocated candidates (0350-0354, 0356-0363, 0365-0369 invalid; 0338 invalid; 0372-0379 valid as Zong, not used) |
| S5 | Wikipedia, "List of cities in Pakistan by population" (2023 census, PBS), https://en.wikipedia.org/wiki/List_of_cities_in_Pakistan_by_population (2026-11-20) | facts | city populations |
| S6 | Wikidata Query Service (P625 coordinates), https://query.wikidata.org (2026-11-20) | CC0 | all `places` coordinates |
| S7 | News on PTCL–Telenor Pakistan acquisition and PTML merger: Dawn https://www.dawn.com/news/1964301, https://www.dawn.com/news/1984758 ; Profit https://profit.pakistantoday.com.pk/2026/01/01/ptcl-closes-telenor-deal-rises-to-second-largest-telecom/ ; ProPakistani https://propakistani.pk/2026/07/02/telenor-pakistan-formally-amalgamates-into-ptml-following-statutory-approvals/ , https://propakistani.pk/2026/09/14/govt-again-blocks-ufone-telenors-push-to-rebrand-as-e/ (2026-11-20, via search snippets) | facts | carrier status and shares (Jazz ~38 %, Zong ~26 %, PTML ~35 %) |
| S8 | UNHCR Pakistan: population-of-concern overview Apr 2026 (~841k PoR holders), https://www.ecoi.net/en/file/local/2140338/Pakistan%20Population%20of%20Concern_April%202026_v1_Revised.pdf ; Dawn "Two million Afghans still living in Pakistan: UNHCR", https://www.dawn.com/news/1963312 (2026-11-20, via search snippets) | facts | `cultures: af` share 0.007 |
| S9 | SECP digital-lending whitelist, as reported by PhoneWorld 2025-12-30, https://www.phoneworld.com.pk/25-secp-approved-loan-apps-operating-in-pakistan/ (2026-11-20); SECP whitelist page https://www.secp.gov.pk/?p=43412 (PDF not opened) | facts | which nano-lending apps are licensed (Paisayaar/JingleCred, Aitemaad/4Sight, SmartQarza/Goldlion, Fauri Cash/Pakisnova, PakCredit/VisionCred …). Barwaqt was not on the Dec 2025 list and is not included |
| S10 | JazzCash mobile-account page (mirror on netlify.app of jazzcash.com.pk/mobile-account/overview, search snippet): "confirmation SMS from 8558" (2026-11-20) | facts | JazzCash sender 8558 (medium confidence: mirror, not the official domain) |
| S11 | ProPakistani 2017 "7 best mobile banking services Pakistan", https://propakistani.pk/2017/10/31/7-best-mobile-banking-services-pakistan/ (snippet: confirmation SMS from 3737) | facts | easypaisa sender 3737 (medium-high) |
| S12 | NTISB advisory 53/2023, https://www.cabinet.gov.pk/SiteImage/Misc/files/NTISB%20Advisories/2023/adv-53-23.pdf ; SBP scam advisories (via search snippets) | facts | genuine bank SMS carry a bank short-name sender ID or 4-digit short code |
| S13 | MCB Bank SMS alert page, https://mcb.com.pk/personal-services/sms-alert ("You will receive SMS from 6222") | facts | MCB short code 6222 (high) |
| S14 | ARY News on PTA consumer short codes (8484 device status, 668 SIMs per CNIC, 667 MNP) https://bk.arynews.tv/?p=664358 (snippet) | facts | government short codes (high) |
| S15 | Federal gazetted holidays (Cabinet Division notifications; general knowledge, Iqbal Day restored 2022, Youm-e-Takbeer holiday since 2024) | facts | `holidays` |
| S16 | Google Play store pages `https://play.google.com/store/apps/details?id=<pkg>&hl=en&gl=pk`, fetched 2026-11-20; title and developer checked for each package | facts (package ids) | all 40 `popular_apps` — every id resolved to the named app |

## Authored (hand-written / AI-drafted, no external source)

- **Name pools and weights** (female 114, male 129, surnames 172): authored from general
  knowledge of Pakistani naming (Punjabi, Urdu-speaking, Pashtun, Sindhi, Baloch,
  Christian and Hindu minorities). Pakistan publishes no official given-name or surname
  frequency statistics; weights are rough tiers, not measured. Faker `en_PK` (MIT) was
  inspected and NOT used (unweighted baby-name list, mostly male).
- **Nicknames, contact-saving conventions** (comments in `names`): authored.
- **Streets**: authored list of common Pakistani road names (Mall Road, Shahrah-e-Faisal,
  Jinnah Road …) plus numbered streets/galis, which is how most residential addresses
  are written.
- **Postcodes and districts**: authored from general knowledge of Pakistan Post GPO codes
  and well-known neighbourhoods; approximate.
- **City centre coordinates**: general knowledge (city centroids, not private places).
- **Email domain shares**: authored estimate (Gmail strongly dominant).
- **Service senders, confidence**:
  - high: 6222 (MCB), 8484/668 (PTA), 3737 (easypaisa), carrier brand masks.
  - medium: 8558 (JazzCash), 8400 (NADRA CNIC tracking), 9966 (FBR ATL), 8300 (ECP) —
    widely reported short codes, not confirmed on an official page during this session.
  - authored/plausible (exact mask spelling unverified): bank masks (HBL, UBL, MeezanBank,
    ABL, BankAlfalah, NBP, BankIslami, FaysalBank), wallet masks (JazzCash, easypaisa,
    SadaPay, NayaPay, UPaisa), lender masks (Paisayaar, SmartQarza, Aitemaad), couriers,
    retail, airlines, utilities. Alphanumeric masks are max. 11 characters in Pakistan.
- **Language shares** (ur 0.7 Roman Urdu, en 0.3): authored estimate.

## Gaps

- PTA's own current mobile-code allocation table could not be fetched (pta.gov.pk refused
  connections); unallocated blocks rest on the ITU-published plan (S1) + libphonenumber (S4)
  + absence from every operator listing.
- No official fiction/drama number range exists for Pakistan (none found) -> `fiction: null`.
- SECP whitelist PDF (Nov 2026 revision) not opened; app list reflects the Dec 2025 list.
