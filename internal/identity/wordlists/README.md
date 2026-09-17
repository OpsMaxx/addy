# Vendored wordlists

These files are **data, not code**, and they are shared.

A device's friendly name is generated in Go by the relay and in TypeScript by
the OpsMaxx client, and the two must agree: a device that is `quiet-otter-41` in
the app and something else in the portal is worse than no name at all, because
the name exists so a person can recognise their own machine in a revoke dialog
under stress.

So the lists live here once, both implementations read these exact files, and a
test pins them identical across the two. Editing one of these files is a
protocol change: a name already shown to a human must keep generating from the
same list, so entries are **appended, never reordered and never removed**.

The same discipline applies to `sas-emoji.json`, which is Matrix's table and is
vendored rather than fetched — a pairing check that needs the network is not a
pairing check.

## Word choice

Every word is chosen to be:

- **concrete and common** — a person has to hold it in their head and say it
  aloud to someone else;
- **unambiguous when spoken** — no homophones of each other within a list;
- **innocuous** — nothing that reads as an insult when paired with a noun, and
  nothing that could embarrass someone reading their device list at work.

The third rule is why this list is hand-written rather than lifted from a
dictionary of frequent adjectives. Random pairing from a large list eventually
produces a sentence somebody has to explain.
