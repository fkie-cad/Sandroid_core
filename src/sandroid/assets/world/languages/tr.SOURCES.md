# Sources: languages/tr.yaml

## Provenance
All content in `tr.yaml` (threads, service SMS, calendar titles, file names, notes, call names) is **authored**: written by an AI model (Claude, Anthropic) on 2026-11-20 for this pack. No external text was copied or adapted, and no web sources were used.

Licence: authored material, no third-party content. It may be used under the project's licence.

## Conventions
- **Register:** family, partner and friends use *sen*. Neighbours mostly use *siz*, and close neighbours use *sen*. Every service uses formal *siz* forms ("-nız/-niz", "...ınız", "Sayın ..."). Polite workplace phrases such as *Kolay gelsin* and *X Bey* appear in the colleague threads.
- **Texting habits:**
  - abbreviations: `slm` (selam), `mrb`, `nbr` (naber), `tmm` (tamam), `tşk`/`tşkler`, `eyv` (eyvallah), `saol` (sağol), `dk` (dakika)
  - common words: *aynen*, *kanka*, *abi/abla*, *canım*, *aşkım*, *hadi*
  - laughter written as `sjsjsj`
  - spoken forms: *geliyo*, *napıyon*, *görüşemiyoz*, *gidecem*, *konuşcaz*, *kalcam*, *bişey*, *burda*
  - dropped diacritics in some casual messages (*Iyi*, *Izledim*)
  - a common real-world error kept on purpose: *Seninde* written together instead of *Senin de*
- **Placeholders without suffixes:** Turkish case suffixes depend on vowel harmony, which the generator cannot know. Placeholders therefore never take a suffix. Sentences use invariant frames instead: `saat {time}`, `{date} tarihinde`, `{day} günü`, `{place} önünde/civarında`, `{city} tarafında/yönündeki`, `{partner_first} ile`, `{amount} tutarındaki`, `{tracking} numaralı`.
- **Service SMS style:**
  - bank OTP texts carry the `B{digits:3}` suffix that Turkish banks append
  - retail promotions carry the commercial-message opt-out line ("SMS almamak için RET yazıp ... gönderin") and a `Mersis:` number
  - government texts use generic wording (nüfus müdürlüğü, tebligat) and name no portal
  - no brand names and no emoji
- **Emoji:** `emoji: true` is set on a thread when at least one of its messages contains emoji (22 of 55 threads).
- **File names:** ASCII-folded, as is common for Turkish documents (e.g. `Kira_Sozlesmesi`), with one diacritic example (`Biniş_Kartı`). There is no `{date}` in file names because the TR date format contains "/".
- **Diaspora:** the pack also suits Turkish speakers in DE/NL/AT (country packs list `tr` under `cultures`). Diaspora texting often code-switches into German or Dutch ("Termin", "tamam ich komm"). This pack does not model that, which is a possible future `tr-DE` variant.
- **Gender:** a few family threads imply roles (anne, baba, abla). Like the other packs, this assumes the generator applies family threads loosely.
- **Placeholders used:** `{owner_first}`, `{first}` (always the other person), `{partner_first}`, `{place}`, `{city}`, `{time}`, `{day}`, `{date}`, `{amount}`, `{digits:N}`, `{code}`, `{tracking}`, `{shop}`, `{bank}`, `{courier}`. `{last}` appears only in file names.
- **call_names:** `grandma`, `grandpa` and `partner` were added beyond the schema's `mom`/`dad` example. Turkish has two words for grandmother, *Anneannem* (mother's mother) and *Babaannem* (father's mother). The pack uses Anneannem.
