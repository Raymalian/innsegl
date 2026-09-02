# Runbooks

Operator procedures for Innsegl. They are written for someone reading at 3am
with something broken, so they are short on rationale and long on exact
commands, and every command in them is one this repository actually ships.

Where a command an operator would reasonably expect **does not exist yet**,
each runbook says so in as many words and gives the manual equivalent. A
runbook that instructs someone to run a flag we never shipped is worse than one
that admits the gap; each document ends with a table of the gaps it had to work
around.

| | |
|---|---|
| [`index-rebuild.md`](index-rebuild.md) | Rebuilding the Postgres hot tier from a backup, and adjudicating the result against the sealed segments and their Rekor anchors. Doc 05 §2's required deliverable. |
| [`trust-domain-re-rooting.md`](trust-domain-re-rooting.md) | Recovery from a trust-domain root compromise (threat model A1). What is recoverable, what is not, and what an operator must not pretend. Doc 04 §5.1's required deliverable. |
| [`verify-rebuilt-index.sh`](verify-rebuilt-index.sh) | The executable check `index-rebuild.md` §6 runs: does the index you just rebuilt hold the event hashes the segments sealed? |
| [`verify-rebuilt-index-selftest.sh`](verify-rebuilt-index-selftest.sh) | The gate, watched failing. Twenty-two cases: green on good material, red on each defect, and the Merkle derivation pinned against the constants the Go sealer commits. |

## The one idea these share

**Losing the database loses convenience, not proof.**

The hot tier is an index. It is backed up like any database and restored like
any database. The sealed segments are not backed up — they are already
immutable, under object lock, with their Merkle roots in a transparency log
somebody else runs. The correct verb for a segment is *verify*, never *restore*,
and the operational consequences of that asymmetry are §2 of
`index-rebuild.md`: the tempting action during an outage is exactly the wrong
one, two of the wrong ones succeed silently, and the runbook says what to type
instead.

The same asymmetry is why A1 is survivable at all. A compromise of the trust
domain root cannot reach backwards into records already written (I4), and
verification never needed our database to begin with (I5) — so what a root
compromise destroys is the meaning of identities minted under it, not the
ledger and not the log.

## Running the check

```bash
runbooks/verify-rebuilt-index.sh --segments ./segments --index-hashes index.hashes
runbooks/verify-rebuilt-index-selftest.sh
```

The self-test is not wired into CI — `.github/` is owned elsewhere — so run it
by hand after changing the gate. It needs nothing but a POSIX shell and one of
`sha256sum`, `shasum` or `openssl`, and it reads the committed golden fixtures
read-only.

The gate proposes test-catalogue ID **SEG-007**. It is not in doc 07: the
catalogue is normative and is not edited from here.
