# Sources: countries/fr.yaml

All sources accessed 2026-11-20 unless noted.

| ID | Source | Licence | What was taken |
|----|--------|---------|----------------|
| S1 | INSEE, "Fichier des prénoms" édition 2025 (births 1900-2024), https://www.insee.fr/fr/statistiques/8595130 (prenoms-2025-nat_csv.zip) | Licence Ouverte / Etalab 2.0 (CC-BY compatible), attribution "INSEE" | first names, births 1950-2006, counts; accent variants folded |
| S2 | ARCEP plan de numérotation (consultation 2025, annexe 1), https://www.arcep.fr/uploads/tx_gspublication/consultation-plan-de-numerotation-2025_Annexe-1-modifiee-diff-officiel.pdf | official (facts) | mobile ranges; "Numéros pour œuvres audiovisuelles" = `fiction` (01 99 00, 02 61 91, 03 53 01, 04 65 71, 05 36 49, 06 39 98 + 4 digits) |
| S3 | ARCEP MAJNUM (all attributed blocks), https://extranet.arcep.fr/uploads/MAJNUM.csv (Last-Modified 2026-11-13) | open data (facts) | `realistic` prefix→operator (prefixes ≥90% held by one operator); blocks with no attributaire → `unallocated` |
| S4 | Wikipedia (fr), "Liste des noms de famille les plus courants en France" (INSEE births 1891-1990 counts) | used as facts | 200 surnames with counts |
| S5 | INSEE immigrants and descendants by origin, https://www.insee.fr/fr/statistiques/3633212 , https://www.insee.fr/fr/statistiques/4186761 | facts | `cultures` shares (immigrants + descendants) |
| S6 | Wikipedia page coordinates (MediaWiki API) | facts | `places` |
| S7 | Google Play / mirror listing URLs | facts | `popular_apps` package ids |

## Processing notes
- INSEE counts births in France, so the majority pool already contains French-born names of Maghreb origin (Mohamed, Mehdi, Karim, Yanis). They were kept because they are part of French naming; the Maghreb diaspora share is listed under needed culture packs.
- Unaccented INSEE spellings were folded into the accented form (Jerome → Jérôme) where a variant exists.

## Authored / estimated
- Streets: authored from commonly cited lists of the most frequent French street names (Rue de l'Église, Place de l'Église, Grande Rue, ...).
- Cities (rounded populations, sample postcodes/districts), email domains, services, nicknames: authored.
- Carrier shares: approximate (ARCEP publishes no per-operator shares; secondary sources disagree). sim_operator strings not verified on a device.
- Places hand-entered (no Wikipedia coordinates): Grande Plage (Biarritz), Plage du Prophète, Marché d'Aligre, Marché des Capucins. Lake points moved to shore towns.
- `regional: true` holidays apply only in Alsace-Moselle.

## Validation
`phonenumbers` 9.0.43: unallocated 073x/0740-0742/0747x samples valid MOBILE; landline fiction ranges valid FIXED_LINE; **mobile fiction 06 39 98 xx xx is INVALID** in libphonenumber.
