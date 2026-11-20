# Sources: languages/pt-BR.yaml

## Provenance and licence
- **All content is authored**: written by Claude (AI) on 2026-11-20 for Sandroid. No external text was copied; no web sources were used.
- Licence: authored material, no third-party content. No real persons; no brand names in templates (senders come from the country pack via `{courier}`, `{bank}`, `{shop}`).
- "pix" appears sparingly (family, friend, bank SMS, a file name, a note). It is the Banco Central do Brasil's public instant-payment system and works as a generic verb in Brazilian texting ("te mando um pix"); it is not a commercial brand of any sender.

## Conventions
- Register: informal `você`/`vc` between family, partner, friends and neighbours; services use neutral `você` or impersonal forms, which is the real norm for Brazilian service SMS (`o senhor/a senhora` would read stiff).
- Texting habits: `vc` (você), `tb/tbm` (também), `blz` (beleza), `vlw` (valeu), `kkkk` (laughter), `pfv` (por favor), `obg` (obrigado/a), `bjs` (beijos), `hj` (hoje), `agr` (agora), `qdo` (quando), `gnt` (a gente), `mt` (muito), `fds` (fim de semana), `to/tô` (estou), `bora`, `fechou`, `show`, `oi sumida`, `niver`; missing accents and lowercase replies.
- Service SMS are written without accents (Brazilian SMS often drop them for GSM-7); the bank, boleto, CPF ("CPF final {digits:3}") and código de verificação patterns follow common Brazilian practice.
- The `rail` kind uses intercity-bus wording (rodoviária, poltrona, plataforma), because long-distance passenger rail barely exists in Brazil and bus tickets fill that role.
- `emoji: true` is a thread-level flag: at least one message in the thread contains emoji (schema v1 has no per-message flag). About 43 % of threads carry emoji. Service SMS contain no emoji.
- `{first}` always means the other person of the thread; third parties are hard-coded names (Ju, Rafa, Carla).
- Placeholders used: `{owner_first} {first} {partner_first} {place} {city} {time} {day} {date} {amount} {digits:N} {code} {tracking} {shop} {bank} {courier}`, and `{last}` in file names only (as in the schema example). File names avoid `{date}` because Brazilian dates contain `/`.
- Added keys in `call_names` beyond the schema example: `grandma`, `grandpa`, `partner`.
- File `kind` vocabulary: invoice, contract, payslip, statement, tax, cv, ticket, insurance, letter, form, manual, receipt, scan, other.
