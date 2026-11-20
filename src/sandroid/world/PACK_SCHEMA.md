# World data packs: schema v1.1

These packs feed `sandroid.world.generator`, the deterministic "lived-in
world" generator. It builds a social graph (the owner plus 25 to 250 people)
and derives phone contents from it: contacts, SMS, call log, calendar, photo
metadata, files and notes. It uses no Faker and no Python `random`: it reads
only these YAML packs and a seed.

Built-in packs live in `sandroid/assets/world/`. User packs in
`$XDG_CONFIG_HOME/sandroid/world/{countries,languages,photos}/` (default
`~/.config/sandroid/world/`) replace the built-in pack with the same id (file
stem) as a whole. `sandroid.world.packs.validate_pack()` checks a pack;
`PackSet().validate_all()` checks every pack.

All files are UTF-8 YAML, parsed with the safe loader. Every pack has a
sibling `<pack>.SOURCES.md` listing its sources and licences. Licence rule:
facts, public-domain, CC0 or CC-BY/ODbL-compatible material only; nothing
NonCommercial, no viral ShareAlike, no scraped proprietary lists.

v1 packs (`schema: 1`) are read as v1.1; v1.1 only adds optional fields and
relaxes types. Validator results are **errors** (the pack is wrong or
unusable) or **warnings** (a content gap or a soft limit; the pack works).

## Changes from v1

| Area | v1.1 |
|---|---|
| Service kinds | adds `mobile_money`, `lender`, `betting`. `loan` is an alias of `lender` (also as a `service_sms` key). Unknown kinds warn. |
| `sender_type` | `alphanumeric`, `number` or `shortcode`; optional `label` (the brand behind a number or short code). |
| Names | entries may carry `g: [tags]`; `names.groups: {tag: share}`; optional `display_variants: [{pattern, w}]` and `single_name_share`. |
| Holidays | rule grammar below; flags `regional`, `observance`. |
| `call_names` | value is a string or a list of strings; may contain `{first}`. |
| Text entries | `service_sms`, `notes`, `calendar`, `files` entries are a string or a mapping `{text or title or name, regions, script, ...}`. |
| Threads | messages stay `[speaker, text]`; thread-level `regions`, `script`, `emoji`. |
| Emoji | the generator detects emoji per message; the `emoji` flag is informational. |
| Placeholders | adds `{date_file}`, `{balance}`, `{fee}`, `{last}`, `{state}`, `{district}`. |
| Optional fields | cities: `state`, `timezone`; phone entries: `city`, `note`, `source`; `trunk_prefix: ""`; `postcode_pattern`; `currency.sms_format`; language `weekdays`. App categories are an open set. |
| Devices | optional country key `devices: [{make, model, codename, min_sdk, max_sdk, w}]`: the persona phone (photo EXIF; the codename later feeds Build.DEVICE/BOARD and the fingerprint). `max_sdk: null` = still supported. Without it the generator draws from a built-in list of Google Pixels (4a, 5, 6, 6 Pro, 6a, 7, 7a, 8, 8 Pro, 8a, 9, newer ones weighted higher). With `target_sdk`, only phones with `min_sdk <= target_sdk <= max_sdk` are drawn; when none fits, generation fails (a device set in the world spec is used anyway, with a warning). A non-Google make warns: apps will see a Pixel, because the emulator bypass only spoofs Pixel fingerprints. |
| Photos manifest | adds `file`, `original_had_exif`, `original_had_gps`, `downscaled`, `sha256_original`, `bytes_original`, `width_original`, `height_original`; licence `authored` for generated images; `original_exif_stripped` is dropped (a warning if present). |

## Country pack: `countries/<cc>.yaml`

`<cc>` is the ISO 3166-1 alpha-2 code in lower case and must equal `country`.

```yaml
pack: country
schema: 1.1
country: de
name: Germany
languages: {de: 1.0}           # shares of locally written text; ids should have a language pack (warning)
timezones: [Europe/Berlin]     # IANA, at least one
date_format: "dd.MM.yyyy"      # Java-style: yyyy yy MM M dd d
time_format: "HH:mm"           # HH H hh h mm a
currency:
  code: EUR
  symbol: "€"
  format: "49,99 €"            # an example amount; separators, decimals and symbol position are read from it
  sms_format: "EUR 49.99"      # optional: how service SMS write amounts
phone:
  country_code: "49"
  trunk_prefix: "0"            # "" when there is none (IT, ES)
  national_format_examples: ["0171 2345678"]
  mobile:
    realistic:                 # allocated to operators: real people may own these numbers
      - {prefix: "151", length: 11, operator: Telekom, city: null, note: "..."}
    unallocated:               # valid format, not allocated; null when unknown (warning)
      - {prefix: "1504", length: 11, note: "...", source: S3}
    fiction:                   # official drama/fiction ranges; null when none (warning)
      - {range: "17139200000-17139200099", note: "..."}
  landline:
    cities: [{city: Berlin, area_code: "30", subscriber_length: 8}]
    fiction: [{range: "3023125000-3023125999"}]
  validation_note: "how libphonenumber treats the ranges"
carriers: [{name: Telekom, sim_operator: "Telekom.de", mccmnc: "26201", share: 0.35}]
cities:                        # 8+ recommended; lat/lon required
  - {name: Berlin, lat: 52.52, lon: 13.405, population: 3700000, area_code: "30",
     postcodes: ["10115"], districts: [Mitte], state: Berlin, timezone: Europe/Berlin}
streets: [Hauptstraße]         # 40+ recommended
address_format: "{street} {number}, {postcode} {city}"   # {street} {number} {postcode} {city} {state} {district}
postcode_pattern: null         # optional
places:                        # park landmark station airport beach mountain museum stadium market lake
  - {category: park, name: Tiergarten, city: Berlin, lat: 52.5145, lon: 13.3501}
names:
  culture: de
  female: [{name: Sophie, w: 1.0, g: [optional, tags]}]   # 80+ recommended
  male: [{name: Lukas, w: 1.0}]                            # 80+ recommended
  surnames: [{name: Müller, w: 1.0}]                       # 150+ recommended
  groups: {hindi: 0.4, tamil: 0.06}   # optional group shares (see "Name groups")
  nicknames: {Alexander: Alex}
  display: "{first} {last}"           # {first} {last}
  display_variants: [{pattern: "Mama {first}", w: 0.1}]   # optional
  single_name_share: 0.0              # optional: share of people with no surname
cultures: [{culture: tr, share: 0.04}]   # diaspora shares; ids should have a country pack (warning)
email:
  domains: [{domain: gmail.com, share: 0.35}]
  patterns: ["{first}.{last}", "{f}{last}{yy}"]   # {first} {last} {f} {l} {yy} {yyyy} {nn} {digits:N}
services:
  - {sender: DHL, kind: courier, sender_type: alphanumeric}
  - {sender: "28777", label: USPS, kind: courier, sender_type: shortcode}
  - {sender: "+4930...", kind: doctor, sender_type: number}
holidays:
  - {date: "12-25", name: Weihnachten}
  - {rule: easter+1, name: Ostermontag}
  - {rule: "11-thu#4", name: Thanksgiving}
  - {rule: "hijri:10-01", name: Eid al-Fitr}
  - {rule: "lunisolar:diwali", name: Diwali}
  - {date: "10-31", name: Reformationstag, regional: true}
  - {date: "05-10", name: Muttertag, observance: true}
popular_apps: [{package: de.dkb.portalapp, name: DKB, category: banking}]
devices:                       # optional; no built-in pack sets it yet
  - {make: Google, model: "Pixel 8", codename: shiba, min_sdk: 34, max_sdk: null, w: 1.0}
```

### Service senders

- `kind`: `courier`, `bank`, `telecom`, `otp_service`, `doctor`, `pharmacy`,
  `delivery_food`, `ride_hailing`, `airline`, `rail`, `government`, `retail`,
  `utility`, `mobile_money`, `lender` (alias `loan`), `betting`. Other kinds warn
  and get no SMS unless a language pack has templates for them.
- `sender_type: alphanumeric`: the SMS address is the sender id, unchanged.
- `sender_type: shortcode`: the address is the numeric short code. When the
  sender is not numeric (the code is unknown; the validator warns), the
  generator makes a stable 5-6 digit code for it from the seed and keeps the
  sender as `label`.
- `sender_type: number`: `sender` is `+<digits>` or a pattern `+<digits>...`.
  The generator makes a number at the world's number level that starts with
  those digits when the level has such a range, and otherwise any mobile number
  of that level. A prefix never moves the number to a less safe level. A
  `doctor` sender gets a landline only when landlines exist at that level;
  there is no unallocated landline level, so at `unallocated` doctors and
  other number senders get mobile numbers.
- `label`: the brand behind a number or short code (shown as the contact name).

### Holiday rules

| Form | Meaning |
|---|---|
| `date: MM-DD` (or `rule: MM-DD`) | fixed date |
| `easter`, `easter+N`, `easter-N` | days from Western Easter Sunday |
| `MM-dow#n` | n-th weekday of the month, `dow` in `mon..sun`, `n` = 1..5 or -1 (last) |
| `hijri:MM-DD` | tabular Islamic calendar (may differ by a day or two from the observed date) |
| `lunisolar:<name>` | named lunisolar date; the generator cannot compute these and skips them |

`regional: true` holidays are not seeded (the owner's region is unknown).
`observance: true` marks days that are not days off; they are seeded.

### Name groups

With `names.groups`, the generator draws a group by share and then the first
name and the surname from entries tagged with that group or untagged. Without
`groups`, tags only keep the surname in the first name's groups (an untagged
first name takes any surname); the validator warns. Family members share one
group.

### Number levels

The world spec's `numbers:` picks `fiction`, `unallocated` or `realistic`.
When a level has no ranges or its pool is used up, the generator falls back
and records a warning: `fiction` to `unallocated` to `realistic`;
`unallocated` to `fiction` to `realistic`; `realistic` to `unallocated` to
`fiction`. Landlines are used only at a level at least as safe as the mobiles'.
The national significant number of a `prefix` entry is `prefix` plus random
digits up to `length`; a landline is `area_code` plus `subscriber_length`
digits (first digit 2-9); a `range` entry draws inside the range.

### E-mail levels

The world spec's `emails:` picks the domains of generated addresses (the local
parts come from the pack's `patterns` at every level):
`reserved` (default) uses the RFC 2606 domains `example.com`, `example.net`
and `example.org`; `owned` uses the Sandroid config's `world.email_domain`
(without one it falls back to `reserved` with a warning); `realistic` draws
from `email.domains` by `share`. The level is part of `world_fp`, and the
addresses are markers at every level.

## Language pack: `languages/<lang>.yaml`

`<lang>` is a BCP-47 tag (`de`, `pt-BR`) and must equal `lang`.

```yaml
pack: language
schema: 1.1
lang: de
name: Deutsch
weekdays: [Montag, Dienstag, Mittwoch, Donnerstag, Freitag, Samstag, Sonntag]   # optional, needed for {day}
threads:                     # family, partner, friend, colleague, neighbor; 15+ each recommended
  family:
    - msgs: [[p, "Kommst du Sonntag zum Essen?"], [o, "Ja, gegen 12"]]
      regions: [de]          # optional: only for worlds in these countries (or people of these cultures)
      script: Latn           # optional ISO 15924
      emoji: false           # informational
service_sms:                 # keyed by service kind; 5+ per kind recommended
  courier: ["Ihre Sendung {tracking} kommt heute zwischen {time}."]
  bank: [{text: "...", regions: [de], script: Latn}]
calendar:                    # 40+ recommended
  - {title: "Zahnarzt", minutes: 45, kind: appointment}
  - {title: "Geburtstag {first}", all_day: true, kind: birthday}
files: [{name: "Rechnung_{date_file}.pdf", kind: invoice}]   # 30+ recommended
notes: ["Einkaufen: Milch, Brot, Eier"]                       # 20+ recommended
call_names: {mom: Mama, dad: [Papa, Paps], aunt: "Tante {first}"}
```

Speakers: `o` is the owner, `p` the other person. Calendar kinds: appointment,
work, social, sport, travel, birthday, reminder. File kinds: invoice,
contract, payslip, statement, tax, cv, ticket, insurance, letter, form,
manual, receipt, scan, other. `call_names` keys: mom, dad, grandma, grandpa,
partner, sister, brother, aunt, uncle, son, daughter.

### Placeholders

| Placeholder | Value |
|---|---|
| `{owner_first}` | the owner's first name |
| `{first}`, `{last}` | threads: the other person. Service SMS: a contact, or a stranger's name for courier, food delivery and ride hailing. Calendar and notes: a contact. File names: the owner. |
| `{partner_first}` | the owner's partner (templates are skipped when there is none, or in the partner's own thread) |
| `{place}`, `{city}`, `{state}`, `{district}` | a place near home, a city, the home city's state or a district |
| `{time}` | a time of day in `time_format` |
| `{day}` | a weekday name from `weekdays` (templates are skipped without it) |
| `{date}` | a date in `date_format`; in file names "/" becomes "-" |
| `{date_file}` | an ISO date `YYYY-MM-DD` |
| `{amount}`, `{balance}`, `{fee}` | money with the currency symbol, formatted like `currency.format` (`currency.sms_format` in service SMS when set) |
| `{digits:N}` | N random digits |
| `{code}` | a 6-character reference code |
| `{tracking}` | a parcel tracking number |
| `{shop}`, `{bank}`, `{courier}` | a sender of that kind from the country pack (the sending service itself when it has that kind) |

The same placeholder used twice in one text gets the same value. A template
with a placeholder that cannot be filled is skipped, never emitted with a
`{...}` left in it.

## Photos manifest: `photos/manifest.yaml`

```yaml
pack: photos
schema: 1.1
photos:
  - id: wm-0001
    file: files/wm-0001.jpg               # path inside the photo cache
    url: https://upload.wikimedia.org/... # null only for licence: authored
    page: https://commons.wikimedia.org/wiki/File:...
    sha256: "..."                         # of the file as shipped/downloaded
    licence: CC0-1.0                      # CC0-1.0, PDM-1.0 or authored
    author: "..."
    width: 4000
    height: 3000
    bytes: 2345678
    category: food   # food street nature pet interior landmark_generic sky document_like screenshot_like vehicle sport plant
    indoor: false    # may be null (screenshots)
    has_people: false
    country_neutral: true
    country: xx      # required when country_neutral is false
    original_had_exif: true
    original_had_gps: true
    downscaled: false
    sha256_original: "..."   # when downscaled
    bytes_original: 0
    width_original: 0
    height_original: 0
```

The files are not shipped: they are downloaded on first use into
`$XDG_CACHE_HOME/sandroid/world/photos/` and verified by `sha256`. The seeder
strips all original EXIF/MPO/XMP and writes the generator's metadata.

## Time

The manifest holds no absolute date, so one world can be seeded on any day.

- Generated items carry `t_rel_s`. Past items count back from the week anchor,
  local midnight of the Monday on or after the seeding moment, so weekend
  outings stay on weekends; an SMS conversation, photo group or item that
  would land after the seeding moment moves back one week, so the newest
  items sit just before it. Future calendar events (`t_rel_s < 0`) count
  whole days and a time of day from the seeding day, so they always lie
  ahead.
- A text that names a date keeps a slot `{@n}` in place of `{date}`,
  `{date_file}` or `{day}`; `date_slots[n]` holds the slot's own `t_rel_s`, its
  kind and the date pattern (or the weekday names). Rendering fills it in for
  the real anchor.
- Holidays and birthdays keep their `rule` and an `occurrence` index: 0 is the
  latest date of the rule up to 60 days after the anchor, 1 the one before.
  Holidays that fall before the world's history are left out when rendering.
  Birthdays are yearly recurring events: their occurrence-0 date may lie
  before the start of a short history (for example a birthday ten months ago
  in a `90d` world); the recurrence carries it forward.
- `WorldManifest.render(anchor)` returns the world with absolute `ts_ms` (and
  `end_ms` for events) and final texts; `markers(anchor)` works on that.
  `world_fp` does not depend on the anchor.
