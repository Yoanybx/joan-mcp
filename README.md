# joan-mcp

MCP server (stdio) for **JOAN** — the language and contract system for
verifiable agreements between agents and humans.

**Doctrine D-19: JOAN judges only.** It mints nothing, seals nothing,
executes nothing and pays nothing. Given an artifact — a chain evidence
package, a policy permit, a signed event delivery — it returns a verdict
that names exactly what was checked: `VALID`, `INVALID`, or
`NOT_VERIFIABLE`. JOAN never accepts an artifact on trust. The proof of a
judged agreement is sealed by [OMTIVO](https://dashboard.omtivo.com/agents/),
its attestation layer. *Agree in JOAN, prove in OMTIVO.*

## Run it (one line)

Add to your MCP client configuration:

```json
{
  "mcpServers": {
    "joan": {
      "command": "npx",
      "args": ["-y", "joan-mcp"]
    }
  }
}
```

Zero dependencies. Node >= 18. MCP over JSON-RPC 2.0, newline-delimited
(stdio), protocol version 2024-11-05. No account, no credential, no
network trust: the judge is fully offline and local.

## Tools

- **`joan_judge`** — offline verdict over a chain evidence package.
  Judges `MT-BRIDGE-PROOF-1` and `MT-ATTESTATION-PROOF-1`: verdict plus
  components, and for attestations the five predicates (`HASH_MATCH`,
  `FILE_SIZE`, `SCHEMA_VALID`, `TIME_BOUND`, `MULTI_SIG`) and attribution
  (`ANCHORED` when the supplied published anchors match; otherwise
  `UNANCHORED`). Any other format returns `NOT_VERIFIABLE`.
- **`joan_validate_permit`** — pre-execution validation of an
  `MT-POLICY-PERMIT-1` permit: closed schema, `ALLOW` decision,
  single-use, the service's ML-DSA-87 signature, validity window, and
  exact binding to the expected recipient, provider, currency and
  amount. Validation only — it never consumes the permit and never
  executes anything.
- **`joan_receive_delivery`** — intake for signed
  `MT-WEBHOOK-DELIVERY-1` event deliveries: the ML-DSA-87 signature over
  the exact body bytes is judged first; each event is applied exactly
  once and replays return `DUPLICATE`. Receiving never executes anything.

## Environment (optional)

- `JOAN_INTEGRATION_DIR` — path to the JOAN-side adapter tree. Defaults
  to the adapter bundled inside this package; set it only to judge with
  a different adapter build.
- `JOAN_INBOX_STORE` — path to the persistent inbox store used by
  `joan_receive_delivery`. Defaults to a temp-dir file.

## Honest state

- **Public alpha, pre-1.0.** The JOAN language itself (parsing,
  checking, compiling JOAN source) is *not* in this server: those are
  Rust crates in the JOAN repository and no tool here pretends to run
  them. JOAN's own canonical hash is likewise not substituted by the
  chain's canonicalization.
- **Testnet.** The judge runs today against testnet evidence (chain
  `million-tower-testnet-1`). Published anchors for attribution live in
  the JOAN manifest: <https://dashboard.omtivo.com/agents/joan/joan.json>
  (field `anchors`). No production network, no real money, nothing for
  sale.
- **No hosted endpoint.** joan-mcp is stdio-local only; there is no
  remote MCP endpoint, no API key and no metering.

Manifest, documentation and measured evidence:
<https://dashboard.omtivo.com/agents/joan/>

Publisher: OMTIVO — Preeminent Laboratories LLC.
