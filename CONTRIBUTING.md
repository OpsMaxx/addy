# Contributing to addy

## Read the design first

`docs/DESIGN.md` is the design of record, and most of its value is in the
corrections it already carries — decisions that were made, broken by review, and
remade. A change that reopens one of those is not automatically wrong, but it
needs to say which paragraph it disagrees with and why.

**The design document is not edited in place.** Corrections land as a dated
status blockquote at the top, body left unedited, so the reasoning stays
readable. This is the convention the sibling repo uses for the same purpose.

## The rules that CI enforces, and why each exists

| Rule | Enforced by | Why |
|---|---|---|
| The retired OpsMaxx product name appears nowhere | `internal/repocheck` | Inherited from the sibling repo from day one, so the check never needs an exemption |
| No known vulnerable dependency | `govulncheck` | The HPKE library has an open advisory below v1.6.3; a pin that drifts under it must fail the build, not ship |
| `gofmt` clean, `go vet` clean | CI | The whole static gate |
| Tests pass before anything is built | CI job order | A red test should fail the build, not produce an artifact nobody checked |

## Security-critical code

Three areas are held to a higher standard than the rest, because nothing below
them enforces the boundary:

- **`internal/roster/`** — the hash-chained device log is the control that makes
  the headline claim true. `adversary_test.go` is a deliberately malicious server
  harness, and a change here that does not extend it is incomplete.
- **`internal/objects/`** — the object store has no bucket policies, so addy's
  own authorization layer is the *only* thing between one user's prefix and
  another's. Every cross-user verb gets its own refusal test.
- **`internal/pair/`** — the SPAKE2 implementation is vendored and reviewed as
  our own code. Treat a change to it as a change to cryptography, not to a
  dependency.

## Vendored code

Some dependencies are vendored rather than pinned: the SPAKE2 implementation
(unmaintained, single non-GitHub host, and the most security-critical primitive
in the system) and the SAS emoji table (a pairing check that needs the network is
not a pairing check). Vendored code records its upstream commit and is reviewed
as ours.

## Licensing

addy is MIT and stays MIT. No GPL, AGPL, LGPL or SSPL dependency may enter the
tree. Reimplementing a documented protocol from its specification is fine and is
where most of the savings are; copying an implementation is not. Running an
unmodified upstream container as a separate process is fine — that is mere
aggregation, and it is how the service wizards work.
