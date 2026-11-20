# Sources: languages/es.yaml

## Provenance and licence
- **All content is authored**: written by Claude (AI) on 2026-11-20 for Sandroid. No external text was copied; no web sources were used.
- Licence: authored material, no third-party content. No real persons; no brand names in templates (senders come from the country pack via `{courier}`, `{bank}`, `{shop}`).

## Conventions
- Register: `tú` between family, partner, friends and neighbours (one neighbour opener uses `suyo`, as a first contact would); services use `usted` or impersonal forms.
- Pan-Hispanic pack (used by ES and Latin America). Spain-leaning threads use *vale, quedamos, finde, billete, padel, ITV*; Latin-American-leaning threads use *tqm, ahorita, celu, carro, prender, mijo, asado, dale*. Templates avoid country-specific IDs (no DNI/CURP/RFC/CUIT).
- Texting habits: `q` (que), `tqm` (te quiero mucho), `bss` (besos), `porfa` (por favor), `ntp` (no te preocupes), `grax` (gracias), `jajaja`, `cumple` (cumpleaños), `finde` (fin de semana), `tranqui`; missing `¿ ¡` and accents; some lowercase-only messages.
- Service SMS are written without most accents (á, í, ó, ú are outside GSM-7, so real Spanish SMS often drop them); `ñ` is kept (GSM-7).
- `emoji: true` is a thread-level flag: at least one message in the thread contains emoji (schema v1 has no per-message flag). About 37 % of threads carry emoji. Service SMS contain no emoji.
- `{first}` always means the other person of the thread; third parties are hard-coded names (Laura, Diego, Marta, Lucia).
- Placeholders used: `{owner_first} {first} {partner_first} {place} {city} {time} {day} {date} {amount} {digits:N} {code} {tracking} {shop} {bank} {courier}`, and `{last}` in file names only (as in the schema example). File names avoid `{date}` because Spanish dates contain `/`.
- Added keys in `call_names` beyond the schema example: `grandma`, `grandpa`, `partner`.
- File `kind` vocabulary: invoice, contract, payslip, statement, tax, cv, ticket, insurance, letter, form, manual, receipt, scan, other.
