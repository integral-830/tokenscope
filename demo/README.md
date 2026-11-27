# Live demo: TokenScope on a program it did not write

`escrow-anchor/` is the Anchor escrow from the Solana Foundation
[program-examples](https://github.com/solana-developers/program-examples/tree/main/tokens/escrow/anchor)
repository, copied unmodified from commit `f766367` (MIT, see `escrow-anchor/LICENSE`). It uses
`token_interface` and `transfer_checked`, so it accepts Token-2022 mints. It is excluded from the
TokenScope workspace and keeps its own lockfile.

`specs/` describes it to `tokenscope sbf-run`: two Token-2022 mints, the maker's and taker's
associated token accounts, the offer PDA, the vault ATA, the Anchor instruction bytes
(discriminator + arguments) and the checks. Nothing in TokenScope is specific to this program.

| Spec | Setup | Check | Result |
|---|---|---|---|
| `escrow-fee-on-wanted-token.json` | 2% transfer fee on mint B | maker receives `token_b_wanted_amount` | fails: wanted 1000, maker received 980 (20 withheld) |
| `escrow-fee-on-offered-token.json` | 2% transfer fee on mint A | `take_offer` / `refund_offer` succeed | both revert with Token-2022 error 35 |

`control/` runs the same program and the same calls with plain Token-2022 mints (no transfer fee).
There every check holds: the maker receives exactly 1000, `take_offer` and `refund_offer` succeed and
the refund returns the full 1000. The findings above come from the fee, not from the checks.

| Control spec | Calls | Result |
|---|---|---|
| `escrow-no-fee-take.json` | `make_offer`, `take_offer` | 0 findings |
| `escrow-no-fee-refund.json` | `make_offer`, `refund_offer` | 0 findings |

Error 35 is `AccountHasWithheldTransferFees`. The vault keeps the withheld fee, and both
instructions close the vault, which Token-2022 refuses while withheld fees remain. The offer can be
neither taken nor refunded until somebody runs `HarvestWithheldTokensToMint` on the vault
(permissionless; after it `take_offer` succeeds). These are limits of an educational example with
fee-bearing mints, not an attack on a deployed protocol.

Run it locally (needs `cargo-build-sbf` 4.5.0 and platform-tools v1.58, see `docs/toolchain.md`):

```sh
cargo build --release -p tokenscope-cli
./scripts/run-live-demo.sh target/release/tokenscope
```

The script exits 0 only when TokenScope reports exactly the rule IDs in `expected-findings.txt` and the
control runs report nothing, so
the [Live demo workflow](../.github/workflows/live-demo.yml) is green while the findings are found
and turns red if TokenScope stops finding them.
