# it.yaml: sources

## Origin and licence
- All content (threads, service_sms, calendar, files, notes, call_names) is **authored**: AI-written by Claude (Anthropic) on 2026-11-20 for Sandroid.
- No external text was copied or adapted; no web sources were used. No third-party licence applies.
- Service SMS are generic imitations of common message types; they contain no brand names (the sender comes from the country pack).

## Conventions
- Register: `tu` between family, partner, friends, colleagues and most neighbours (one formal `Lei` neighbour thread); service SMS use `Lei` or impersonal forms. App-style OTP, delivery and ride SMS use `tu`, as many real Italian app/bank SMS do.
- Texting habits used: cmq (comunque), nn (non), xké (perché), tvb / tvtb (ti voglio (tanto) bene), grz (grazie), tranqui (tranquillo), raga (ragazzi), tt (tutto), amo (amore), ahahah; missing accents and apostrophes ("e" for "è", "l una", "c e"), lengthened letters ("Grazieee", "Sii").
- Emoji: `emoji: true` on a thread means at least one of its messages contains emoji (schema v1 has no per-message flag). About 38% of threads. Service SMS contain no emoji.
- `{first}` is always the other person in the thread; third parties are hard-coded names (Giulia, Marco, Francesca).
- File names avoid `{date}` because Italian dates use "/"; `{digits:N}`, `{code}`, month words instead.

## Region notes
- Italy-centric vocabulary (730, CU, F24, bollo auto, anagrafe, amministratore di condominio, tessera sanitaria). For Ticino/Graubünden (CH) the texts remain natural Italian, but those tax/admin terms are Italy-specific; a CH variant would use e.g. "natel", "Comune/Controllo abitanti", "dichiarazione d'imposta".
- "Onomastico" (name day) is included as a birthday-kind event because it is commonly celebrated in Italy.

## Placeholders used
owner_first, first, partner_first, place, city, time, day, date, amount, digits:N, code, tracking, shop, bank, courier; `{last}` only in file names.
