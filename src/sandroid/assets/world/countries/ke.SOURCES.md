# Sources for `ke.yaml` (Kenya)

Compiled 2026-11-20 by agent countries-3 (KE fork). All URLs accessed 2026-11-20.

| ID | Source | Licence / status | What was taken |
|----|--------|------------------|----------------|
| S1 | Communications Authority of Kenya, *Telecommunication Numbering Plan for Kenya*, April 2026 (CA/SRM/S&N/NNP/APRIL/2026), https://www.ca.go.ke/sites/default/files/2026-04/Numbering%20Plan%20Kenya%20April%202026.pdf | Official government document, facts | Mobile NDC assignments (100-108 Airtel, 110-119 Safaricom, 120 Jambo, 124 Infura, 126 Hidiga, 128 Webtribe, 130 NRG Media, 140-146 Safaricom, 199 test resource, 700-799 table), NSN length 9, open numbering plan (01 and 07 = mobile), geographic area codes, MNC table (section 7.3). Unallocated NDCs derived as "in the 01 mobile space but not in this table". |
| S2 | CA, *Telecommunication Numbering Plan for Kenya*, April 2024, https://www.ca.go.ke/sites/default/files/CA/Numbering%20Plan/Telecommunication%20Numbering%20Plan%20for%20Kenya%20April%202024.pdf | Official, facts | Cross-check: 767 was assigned to Airtel in 2024 but is missing from the 2026 table; 110-117 then (now 110-119). |
| S3 | tech-ish.com, "Safaricom new prefixes 0118, 0140, 0180", 2026-08-10, https://tech-ish.com/2026/08/10/safaricom-new-prefixes-0118-0140-0180/ (plus khusoko.com / techtrendske.co.ke reports of the same date) | Press, facts only | Safaricom launched 0118, 0119, 0140-0143, 0180-0182 on 2026-08-10. 018x is therefore treated as allocated even though S1 predates it. |
| S4 | KNBS 2019 Kenya Population and Housing Census, Vol. IV (ethnic affiliation), as tabulated at https://en.wikipedia.org/wiki/Ethnic_groups_in_Kenya | Facts (census statistics) | Ethnic shares used to weight name pools; `cultures` shares (Somali 2,780,502; Asians 90,527; Arabs 59,021; Europeans 42,868 + 26,753) over 47,564,296. |
| S5 | CA Sector Statistics Reports Q2 and Q3 FY2025/26 (https://www.ca.go.ke/sites/default/files/2026-06/Sector%20Statistics%20Report%20Quarter%203%20%20FY%202025-2026.pdf), as reported by citizen.digital and tech-ish.com | Official statistics, facts | Carrier shares: Safaricom 68.9 %, Airtel 27.6 %, Telkom 0.7 % (Jan-Mar 2026); Finserve/Equitel 1.9 % (Oct-Dec 2025). |
| S6 | KNBS 2019 census urban-centre populations, via https://en.wikipedia.org/wiki/List_of_cities_and_towns_in_Kenya_by_population | Facts | City populations. City-centre coordinates are well-known reference values (rounded to 4 decimals). |
| S7 | Android SIM display names | Authored, best effort | `sim_operator` strings ("Safaricom", "Airtel", "Equitel", "Telkom KE") are not from an official list; MCC-MNC from S1. Note: CA assigns MNC 01 and 02 to Safaricom (02 is the one in live use) and 03 and 05 to Airtel. |
| S8 | OpenStreetMap via Nominatim search API (https://nominatim.openstreetmap.org), © OpenStreetMap contributors | ODbL 1.0, attribution required | Coordinates of all `places` (52 public places; mismatched hits such as "Ngong Hills" → church, "Lake Elementaita" → street were discarded). Street names cross-checked against OSM road names. |
| S9 | Africa's Talking help centre, "How do I set up my sender ID in Kenya", https://help.africastalking.com/en/articles/407085 ; D7 Networks Kenya SMS regulations, https://d7networks.com/sms/kenya/sms-regulations/ | Facts | Sender ID rules (max 11 chars, no spaces, hyphen/underscore allowed; Safaricom requires registration). Confirms well-known IDs MPESA, Safaricom, JUMIA, KENYA POWER. |
| S10 | Public Holidays Act (Cap. 110) and Statute Law (Miscellaneous Amendments) Act 2024 renaming 10 Oct to Mazingira Day; cross-checked with officeholidays.com / timeanddate.com 2026 lists | Facts | Fixed and Easter-based holidays. |
| S11 | Google Play store pages, https://play.google.com/store/apps/details?id=<package>&gl=KE (fetched 2026-11-20) | Facts | Package verification (table below). |
| S12 | libphonenumber (Python `phonenumbers` 9.0.43, Apache-2.0), local check | Apache-2.0, facts | KE mobile regex and validity of realistic/unallocated prefixes (see `validation_note`). |

## Authored / AI-drafted content (mark: authored)

- **Name pools** (`names.female`, `names.male`, `names.surnames`): hand-curated by the agent from general knowledge of Kenyan naming practice (English/Christian given name + ethnic name + family name). No proprietary list (no Forebears scrape) was copied. **Weights are authored estimates**: within each ethnic block they reflect relative commonness, and blocks are scaled by KNBS 2019 ethnic shares (S4). Faker was not used for KE.
- Nicknames (Sheng `-o` forms such as Kevo, Brayo, Collo, Denno) and the contact-display conventions in the YAML comments (teknonyms "Mama Wanjiru", "Baba Otieno"; role tags "Mama Mboga", "Boda Peter", "Fundi Juma"; family terms "Mathe", "Buda", "Shosh", "Guka", "Cucu"): authored from general knowledge.
- `languages` split (en 0.5 / sw 0.5 incl. Sheng), email domain shares and patterns: authored estimates.
- `streets`: well-known public road names (authored list, cross-checked against OSM, S8).
- District lists and post-office postal codes per city: authored from general knowledge (Kenya Postal codes are public facts; unverified individually).
- **Sender IDs** in `services`: MPESA, Safaricom and JUMIA are confirmed by S9. All others (M-SHWARI, AIRTELMONEY, T-KASH, EquityBank, KCB, Co-opBank, NCBA, ABSA_KENYA, FamilyBank, StanbicBank, Timiza, Tala, Branch, Zenka, ZashLoan, M-KOPA, Watu, HustlerFund, KPLC, NCWSC, ZukuFiber, eCitizen, KRA, SHA, NTSA, HELB, NSSF, Kilimall, G4S, PostaKenya, Glovo, Uber, Bolt, Little, KenyaAirway, JamboJet, KenyaRail, NAIVAS, QUICKMART, CARREFOUR, GOODLIFE, BETIKA, SPORTPESA) are **authored best-effort spellings** that respect the 11-char/no-space rule; the exact registered strings were not verifiable from public sources. Kenya Power's ID may appear as "KPLC" or "KENYA POWER" (S9 lists the latter despite the no-space rule).

## Phone ranges: reasoning and confidence

- `realistic`: all from S1 (plus S3 for 018x, which is not used). Confidence high.
- `unallocated`: NDCs 150, 160, 170, 175, 192, 122. They lie in the "01 = mobile" block of the open numbering plan (S1 §1.3) but appear in no assignment row of the April 2026 plan, were not in the April 2024 plan either, were not part of the August 2026 Safaricom launch (S3), and libphonenumber 9.0.43 rejects them (`is_valid_number=False`, `UNKNOWN`). Confidence medium-high: CA can assign new 01x NDCs at any time (it did 140-146 and 018x within the last year), so re-check S1's successor before relying on this.
- `fiction`: null. Kenya has no official drama range. NDC 199 is a CA "shared resource for internal network testing, experimentation and research" (S1) — a test range, not a drama range; it is invalid in libphonenumber and is noted only in comments.
- Observations: libphonenumber still validates 767 (dropped from S1 2026) and 749 (IEBC KIEMS kits), and already treats all of 18x and 135-139 as mobile.

## Google Play verification (S11, gl=KE, 2026-11-20)

| Package | Store title | Developer |
|---|---|---|
| com.safaricom.mpesa.lifestyle | My OneApp | Safaricom PLC |
| com.airtel.africa.selfcare | My Airtel | Airtel Africa |
| ke.co.equitygroup.equitymobile | Equity Mobile | Equity Group |
| com.kcb.mobilebanking.android.mbp | KCB Mobile | (KCB) |
| com.mcoopcash.retail6 | Co-op Bank Mobile Banking App | Co-operative Bank of Kenya Ltd |
| com.nicbank.android | NCBA NOW | Craft Silicon |
| com.loopdfs.consumer | LOOP - Discover, Pay, Grow | NCBA Bank Kenya PLC |
| ke.co.absa.digitalwallet | Timiza | Absa Group Limited |
| com.mode.familykenya.ui | PesaPap, Family Bank | Family Bank |
| com.inventureaccess.safarirahisi | Tala: Fast & Safe Pesa Loan | Tala Mobile |
| com.branch_international.branch.branch_demo_android | Branch: Loans & Mobile Banking | Branch International Financial Services |
| com.zenkafinance.microloans | Zenka Loan App Kenya | Zenka Digital Limited |
| com.kopakash | Zash Loan-Digital Loans Kenya | Zillions Credit Limited |
| ke.zk.pesa.loanapp | ZK Pesa- Instant Loan Solution | Chapeo Capital Limited |
| com.mkopa.app | M-KOPA | M-KOPA Holdings Limited |
| com.watuke.app | Watu | Watu Credit Limited |
| com.whatsapp, org.telegram.messenger, com.facebook.katana, com.instagram.android, com.zhiliaoapp.musically, com.twitter.android | (global apps) | verified 200 |
| com.ubercab, ee.mtakso.client | Uber / Bolt | verified 200 |
| com.craftsilicon.littlecabrider | Little - Rides, Food, Delivery | Craft Silicon |
| com.kenyaairways.prodapp | Kenya Airways | Kenya Airways PLC |
| com.glovo | Glovo | verified 200 |
| com.jumia.android | JUMIA Online Shopping | verified 200 |
| net.kilimall.shop | Kilimall | Kilimall |
| com.naivas.online | Naivas Online | Naivas Online |
| newsapp.citizentv.royalmedia.citizentvnews | Citizen Digital | Royal Media Services |
| ke.go.ecitizen | eCitizen - Gava Mkononi | verified 200 |
| com.kra.mservices | KRA M-Service | Kenya Revenue Authority |
| ke.go.ntsa | NTSA | NTSA |
| ke.go.dha.afyangu | Afyangu | Digital Health Agency |
| com.app.betika.android | Betika | Betika.com |
| com.pevans.sportpesa.ke | SportPesa | Kentech S.L.U. |
| com.afmobi.boomplayer | Boomplay | Transsnet Music Limited |
| com.opera.mini.native | Opera Mini | Opera |

Not found on Play (404) and therefore excluded: OKash (several guessed IDs), `com.safaricom.mysafaricom` (MySafaricom appears merged into My OneApp), `com.inventureaccess.safarirelease` (old Tala ID), `com.kilimall.shop`, `com.timiza` (now an unrelated app "ZAN INVEST" — do not use).
