# Sources: languages/en.yaml (English)

## Authored content
All threads, service SMS templates, calendar titles, file names, notes and call names in `en.yaml` are **authored** (AI-written by Claude, 2026-11-20) for this pack. No text was copied from any website, dataset, chat corpus or real SMS. Licence: authored by the project, free to use.

One shared English pack. Threads and service entries tagged `regions: [us|gb|in|ke|ng|ph]` use wording specific to those countries (e.g. UK 'bins', US 'trash day', Indian UPI debit SMS, Kenyan M-PESA-style confirmations, Nigerian multi-line bank alerts, Philippine e-wallet 'Ref. No.'). Untagged entries are neutral.

Constraints applied: no real persons; no real brand names inside template text (service senders come from the country pack via `{bank}`, `{shop}`, `{courier}`); nothing offensive, political, sexual or medically sensitive beyond everyday appointments; transaction IDs, OTPs, tracking numbers and account fragments are placeholders (`{code}`, `{digits:N}`, `{tracking}`). Every thread or entry containing emoji has `emoji: true`.

## Format references (facts only; no text copied)
Used only to check the *structure* of service SMS (field order, labels, masking, ID shapes). All template wording is authored.
- Safaricom, M-PESA Business Till booklet (PDF), https://www.safaricom.co.ke/images/SM-PESA_BUSINESS_TILL_Booklet_reduce.pdf, accessed 2026-11-20: "<CODE> Confirmed." opener, amount, counterparty, date/time, new balance, separate transaction-cost field.
- Safaricom, M-PESA reversal T&Cs, https://safaricom.co.ke/media-center-landing/terms-and-conditions/m-pesa-reversal, accessed 2026-11-20: fields of a send-money confirmation (name, number, amount, cost).
- SmartSMS Solutions blog, Nigerian debit alert formats, https://smartsmssolutions.com/blog/81-tutorial/1411-what-does-a-debit-alert-message-look-like and .../1412-access-bank-debit-alert-format, accessed 2026-11-20: multi-line "Acct/Amt/Desc/Date/Avail Bal" layout, DR/CR suffixes, masked account numbers.
- TechPinas, GCash reference number guide, https://techpilipinas.com/gcash-reference-number/, accessed 2026-11-20: "Ref. No." label and 13-digit reference numbers on Philippine e-wallet confirmations.
- NPCI Circular 04 (2019-20), standardisation of SMS alerts, https://www.npci.org.in/PDF/AePS/circular/2019-20/Circular%2004%20-%20Standardization%20of%20SMS%20alerts%20to%20customers.pdf, accessed 2026-11-20: masked account "XXXX1234" style and debit wording in Indian bank SMS.
- General knowledge of OTP/SMS-retriever format (`<#>` prefix + app hash line) from the public Android SMS Retriever API documentation.

## Schema notes / proposed extensions (used in this pack)
- `service_sms` kinds `mobile_money` and `loan` (not in the v1 kind list; needed for mobile-money and loan-reminder SMS). Airtime top-up/borrow lives under `telecom`.
- Placeholders `{balance}` and `{fee}` (formatted like `{amount}`), and `{last}` (already used in the schema's files example). `{amount}` is assumed to include the country's currency symbol, so templates never prefix a currency.
- A `service_sms` entry may be an object `{text: ..., regions: [...], script: ...}` instead of a plain string; same for `notes`. Calendar and file entries may carry `regions`/`script`.
- `emoji: true` and `regions`/`script` are set per thread (the thread's message tuples stay `[speaker, text]`).
- `call_names` values are lists of variants (generator picks one) and include more keys than `mom`/`dad` (partner, grandma, grandpa, sister, brother, aunt, uncle, son, daughter). Some values contain `{first}`. A few partner names contain an emoji (contacts can hold them).

## Validation
Loaded with PyYAML 6 (scratch venv) and checked: required keys, 8+ threads per relationship with 2-8 messages each, 5+ templates per service kind, 40-60 calendar entries, 30-50 files, 20-30 notes, only known/proposed placeholders, `emoji` flag matches actual emoji presence.
