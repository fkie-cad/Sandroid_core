# fr.yaml: sources

## Origin and licence
- All content (threads, service_sms, calendar, files, notes, call_names) is **authored**: AI-written by Claude (Anthropic) on 2026-11-20 for Sandroid.
- No external text was copied or adapted; no web sources were used. No third-party licence applies.
- Service SMS are generic imitations of common message types; they contain no brand names (the sender comes from the country pack).

## Conventions
- Register: `tu` between family, partner, friends and colleagues; neighbours mix `vous` (polite, older) and `tu`; all service SMS use `vous` or impersonal forms.
- Texting habits used: slt (salut), cc (coucou), stp (s'il te plaît), jsp (je sais pas), mdr / ptdr (laughing), tkt (t'inquiète), bcp (beaucoup), dac (d'accord), rdv (rendez-vous), dsl (désolé), jsuis / chui (je suis), c (c'est), ya (il y a); dropped apostrophes ("j arrive", "c est") and missing accents ("deja", "a") as in fast phone typing; lengthened letters ("Merciii").
- Emoji: `emoji: true` on a thread means at least one of its messages contains emoji (schema v1 has no per-message flag). About 38% of threads. Service SMS contain no emoji.
- `{first}` is always the other person in the thread; third parties are hard-coded names (Camille, Julien, Nathalie).
- File names avoid `{date}` because French dates use "/"; `{digits:N}`, `{code}`, month words instead.

## Region notes
- France-centric vocabulary (mairie, syndic, point relais, Cerfa form names, avis d'imposition). For BE/CH the texts stay understandable; no septante/nonante numbers are written out, so nothing breaks. CH would say "natel" informally and BE "kot"/"GSM"; not used.
- The doctor SMS mentions a generic "carte d'assurance maladie", not a country-specific card.

## Placeholders used
owner_first, first, partner_first, place, city, time, day, date, amount, digits:N, code, tracking, shop, bank, courier; `{last}` only in file names.
