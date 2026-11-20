# Sources: languages/nl.yaml

## Provenance
All content in `nl.yaml` (threads, service SMS, calendar titles, file names, notes, call names) is **authored**: written by an AI model (Claude, Anthropic) on 2026-11-20 for this pack. No external text was copied or adapted, and no web sources were used.

Licence: authored material, no third-party content. It may be used under the project's licence.

## Conventions
- **Register:** family, partner, friends and neighbours use *je/jij*. One first-contact neighbour thread uses *u*, as is usual between neighbours who do not know each other yet. Banks, government, doctors, pharmacies and utilities use *u*. Couriers, apps, food delivery, ride hailing, OTP and telecom use *je*, as many real Dutch consumer services do.
- **Texting habits:** `ff` (even, "quickly"), `wss` (waarschijnlijk), `idd` (inderdaad), `hvj` (hartelijk gefeliciteerd / "happy birthday"), `thx`, `ok top`, `xx`, `ivm` (in verband met), `jep`, `pff`, `haha`, plus *gezellig*, *lekker*, *balen*. Some sentences drop their final punctuation and capitals on purpose.
- **Emoji:** `emoji: true` is set on a thread when at least one of its messages contains emoji (21 of 55 threads). Service SMS contain no emoji.
- **Regional:** written in Netherlands Dutch. Flemish (BE) users would write *gsm*, *ge/gij*, *amai*, *allez*, *seffens*. The pack contains none of these and is usable but slightly "Hollands" for BE. A separate `nl-BE` pack could be added later.
- **No brands:** `tikkie` (a brand used as a verb) was replaced with *betaalverzoek*. Service senders come from the country pack via `{courier}`, `{bank}` and `{shop}`.
- **Placeholders used:** `{owner_first}`, `{first}` (always the other person), `{partner_first}`, `{place}`, `{city}`, `{time}`, `{day}`, `{date}`, `{amount}`, `{digits:N}`, `{code}`, `{tracking}`, `{shop}`, `{bank}`, `{courier}`. `{last}` appears only in file names. `{date}` appears in one file name (`factuur_{date}.pdf`), which is safe because the NL date format `dd-MM-yyyy` has no slash.
- **Fixed values:** short codes (`1200`, `4411`) and the road name `A12` are illustrative.
- **call_names:** `grandma`, `grandpa` and `partner` were added beyond the schema's `mom`/`dad` example.
