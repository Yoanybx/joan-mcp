#!/usr/bin/env node
/**
 * joan-mcp — MCP server (stdio) for JOAN, the language and contract
 * system for verifiable agreements between agents and humans.
 *
 * DOCTRINE (D-19): JOAN JUDGES ONLY. This server never mints, seals,
 * pays or executes anything. It judges artifacts that other systems
 * produced and returns a verdict that names exactly what was checked:
 *
 *   joan_judge            — the JOAN-side judge over chain evidence
 *                           packages (MT-BRIDGE-PROOF-1 and
 *                           MT-ATTESTATION-PROOF-1). Any other format
 *                           is declared NOT_VERIFIABLE: JOAN never
 *                           accepts an artifact on trust.
 *   joan_validate_permit  — validates an MT-POLICY-PERMIT-1 policy
 *                           permit BEFORE execution: closed schema,
 *                           ALLOW decision, validity window, exact
 *                           binding to (recipient, provider, currency,
 *                           amount) and the service's ML-DSA-87
 *                           signature. Validation only — it does NOT
 *                           consume the permit and executes nothing.
 *   joan_receive_delivery — receives a signed MT-WEBHOOK-DELIVERY-1
 *                           event delivery: the ML-DSA-87 signature
 *                           over the exact body bytes is judged first;
 *                           each event is applied exactly once and
 *                           replays are absorbed as DUPLICATE.
 *
 * WHAT THIS SERVER DOES NOT EXPOSE (by honesty, not by omission):
 *   - Parsing/checking/compiling JOAN language source programs. The
 *     JOAN language crates (joan-syntax, joan-check, joan-compiler…)
 *     are Rust and live in the owner's JOAN repository (public alpha,
 *     pre-1.0); they are not present on this host, so no tool here
 *     pretends to run them.
 *   - JOAN's own canonical hash (joan-canonical: JOAN's strict
 *     canonical JSON with domain-separated SHA-256 digests). That is
 *     a Rust crate in the same repository. It is NOT the chain's
 *     RFC 8785 JCS and NOT MT-DUAL-1024, and this server does not
 *     substitute one for the other.
 *   - Case execution (submitting operations to the enterprise API).
 *     Execution belongs to the caller's own authenticated client;
 *     sealing the resulting proof belongs to OMTIVO.
 *
 * BINDING: the tools wrap the JOAN-side adapter built and verified by
 * Motor 7 (battery-joan 23/23 against the M5 contract, battery-joan-d04
 * 13/13 against the real D04 testnet enterprise backend): the judge
 * delegates to the same mt-verify functions the chain publishes, so a
 * verdict here is the verdict the JOAN side reaches offline, with no
 * service session and no trust in the caller.
 *
 * Zero dependencies. Node >= 18. JSON-RPC 2.0 over stdio,
 * newline-delimited, per the MCP stdio transport.
 *
 * Env:
 *   JOAN_INTEGRATION_DIR  default ~/workspace/torre-millon/joan-integracion-m7
 *   JOAN_INBOX_STORE      default ${TMPDIR}/joan-mcp-inbox.json
 */
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const INTEGRATION_DIR =
  process.env.JOAN_INTEGRATION_DIR || join(homedir(), "workspace", "torre-millon", "joan-integracion-m7");
const INBOX_STORE = process.env.JOAN_INBOX_STORE || join(tmpdir(), "joan-mcp-inbox.json");
const PROTOCOL_VERSION = "2024-11-05";
const SERVER_INFO = { name: "joan-mcp", version: "0.1.0" };

// --- lazy loading of the real JOAN-side adapter ----------------------------
let adapterPromise = null;
function loadAdapter() {
  if (!adapterPromise) {
    adapterPromise = (async () => {
      const imp = (rel) => import(pathToFileURL(join(INTEGRATION_DIR, rel)).href);
      const chainImp = (rel) =>
        import(pathToFileURL(join(INTEGRATION_DIR, "..", "million-tower", "dist", "src", rel)).href);
      const [receipt, gate, inbox, jcs, keys] = await Promise.all([
        imp("src/receipt-verify.mjs"),
        imp("src/permit-gate.mjs"),
        imp("src/webhook-inbox.mjs"),
        chainImp("jcs.js"),
        chainImp("keys.js"),
      ]);
      return {
        verifyJoanReceipt: receipt.verifyJoanReceipt,
        PermitGate: gate.PermitGate,
        PermitError: gate.PermitError,
        WebhookInbox: inbox.WebhookInbox,
        canonicalize: jcs.canonicalize,
        verifyMlDsa87: keys.verifyMlDsa87,
      };
    })();
  }
  return adapterPromise;
}

function toolText(payload, isError = false) {
  return {
    content: [{ type: "text", text: typeof payload === "string" ? payload : JSON.stringify(payload, null, 2) }],
    ...(isError ? { isError: true } : {}),
  };
}

const TOOLS = [
  {
    name: "joan_judge",
    description:
      "Run the JOAN-side judge over a chain evidence package and return its verdict. Judged formats: MT-BRIDGE-PROOF-1 (bridge lock/burn proof) and MT-ATTESTATION-PROOF-1 (enterprise attestation package). The verdict names its components and, for attestations, its predicates (HASH_MATCH, FILE_SIZE, SCHEMA_VALID, TIME_BOUND, MULTI_SIG) and attribution (ANCHORED when the supplied anchors match the published constitution fingerprint / genesis / H(M0); otherwise UNANCHORED). Any other format returns NOT_VERIFIABLE — JOAN never accepts an artifact on trust. The judgment is fully offline: no service, no session. JOAN judges only; it does not seal or mint anything.",
    inputSchema: {
      type: "object",
      properties: {
        package: {
          type: "object",
          description: "The evidence package object (MT-BRIDGE-PROOF-1 or MT-ATTESTATION-PROOF-1).",
        },
        anchors: {
          type: "object",
          description:
            "Optional published anchors for MT-ATTESTATION-PROOF-1: { constitution_fingerprint, genesis_block_hash, initial_validator_manifest_hash } as published by the chain in the JOAN manifest (https://dashboard.omtivo.com/agents/joan/joan.json, field \"anchors\"). Without anchors a package can still judge VALID but its attribution is UNANCHORED.",
        },
      },
      required: ["package"],
      additionalProperties: false,
    },
    run: async (args) => {
      const a = await loadAdapter();
      const judgment = a.verifyJoanReceipt(args.package, args.anchors);
      return toolText({ judge: "JOAN (Motor 7 adapter, mt-verify)", ...judgment }, judgment.verdict === "NOT_VERIFIABLE");
    },
  },
  {
    name: "joan_validate_permit",
    description:
      "Validate an MT-POLICY-PERMIT-1 policy permit against the operation it would authorize, BEFORE any execution: closed schema (an unknown field denies), decision must be ALLOW, single_use must be true, the service's ML-DSA-87 signature must verify under service_public_key_b64, the permit must be unexpired, and it must be bound EXACTLY to the expected recipient, provider, currency and amount (a larger amount is denied MT_BUDGET_EXCEEDED; any mismatch is denied MT_CAPABILITY_DENIED). This tool validates only — it never consumes the permit and never executes the operation.",
    inputSchema: {
      type: "object",
      properties: {
        permit: { type: "object", description: "The MT-POLICY-PERMIT-1 permit object, including service_signature." },
        expected: {
          type: "object",
          properties: {
            recipient: { type: "string" },
            provider: { type: "string" },
            currency: { type: "string", description: "ISO currency code, e.g. USD." },
            amount_minor: { type: "string", description: "Operation amount in minor units, as a decimal string." },
          },
          required: ["recipient", "provider", "currency", "amount_minor"],
          additionalProperties: false,
        },
        service_public_key_b64: {
          type: "string",
          description: "Base64 SPKI of the enterprise service's ML-DSA-87 public key that signed the permit.",
        },
      },
      required: ["permit", "expected", "service_public_key_b64"],
      additionalProperties: false,
    },
    run: async (args) => {
      const a = await loadAdapter();
      const verifyServiceSignature = (permit) => {
        const { service_signature, ...rest } = permit;
        return a.verifyMlDsa87(
          args.service_public_key_b64,
          Buffer.from(a.canonicalize(rest), "utf8"),
          Buffer.from(service_signature, "base64"),
        );
      };
      const gate = new a.PermitGate({
        storeFile: join(tmpdir(), "joan-mcp-validate-only.json"),
        verifyServiceSignature,
      });
      try {
        gate.validate(args.permit, {
          recipient: args.expected.recipient,
          provider: args.expected.provider,
          currency: args.expected.currency,
          amountMinor: args.expected.amount_minor,
        });
        return toolText({ valid: true, consumed: false, note: "Validation only: the permit was NOT consumed and nothing was executed." });
      } catch (err) {
        if (err instanceof a.PermitError) {
          return toolText({ valid: false, code: err.code, message: err.message }, true);
        }
        throw err;
      }
    },
  },
  {
    name: "joan_receive_delivery",
    description:
      "Receive a signed MT-WEBHOOK-DELIVERY-1 event delivery the way a JOAN-side agent does: the ML-DSA-87 signature over the EXACT body bytes is verified first (an invalid signature means the event does not exist: INVALID / MT_EVENT_SIGNATURE_INVALID). Event identity is (event_seq, event_hash), not the delivery id: each event is applied exactly once, replays return DUPLICATE, and the applied set persists across restarts. Receiving never executes anything — it only records; effects are the caller's case logic, over events applied exactly once.",
    inputSchema: {
      type: "object",
      properties: {
        body_text: { type: "string", description: "The exact raw body bytes of the delivery, as a UTF-8 string. Any re-serialization breaks the signature." },
        signature_b64: { type: "string", description: "Base64 ML-DSA-87 signature over body_text." },
        public_key_b64: { type: "string", description: "Base64 SPKI of the delivering service's ML-DSA-87 webhook public key." },
      },
      required: ["body_text", "signature_b64", "public_key_b64"],
      additionalProperties: false,
    },
    run: async (args) => {
      const a = await loadAdapter();
      const inbox = new a.WebhookInbox({ storeFile: INBOX_STORE, publicKeyB64: args.public_key_b64 });
      const result = inbox.receive(args.body_text, args.signature_b64);
      return toolText(
        { ...result, applied_total: inbox.appliedCount, duplicates_total: inbox.duplicateCount, invalid_total: inbox.invalidCount },
        result.status === "INVALID",
      );
    },
  },
];

const TOOL_BY_NAME = new Map(TOOLS.map((t) => [t.name, t]));

async function handle(req) {
  const { id, method, params } = req;
  const isNotification = id === undefined || id === null;
  const reply = (result) => (isNotification ? null : { jsonrpc: "2.0", id, result });
  const replyError = (code, message) =>
    isNotification ? null : { jsonrpc: "2.0", id, error: { code, message } };

  switch (method) {
    case "initialize":
      return reply({
        protocolVersion: (params && params.protocolVersion) || PROTOCOL_VERSION,
        capabilities: { tools: {} },
        serverInfo: SERVER_INFO,
        instructions:
          "JOAN — language and contract system for verifiable agreements between agents and humans. DOCTRINE (D-19): JOAN JUDGES ONLY — it mints nothing, seals nothing, executes nothing; OMTIVO/the chain seals the proof. Tools: joan_judge (offline verdict over MT-BRIDGE-PROOF-1 / MT-ATTESTATION-PROOF-1 packages; unknown formats are NOT_VERIFIABLE, never accepted on trust), joan_validate_permit (pre-execution validation of MT-POLICY-PERMIT-1 permits; never consumes), joan_receive_delivery (signed MT-WEBHOOK-DELIVERY-1 events, applied exactly once). Not exposed: JOAN language source parsing/compilation and JOAN's own canonical hash (joan-canonical) — those are Rust crates in the owner's JOAN repository (public alpha, pre-1.0) and are not present on this host.",
      });
    case "ping":
      return reply({});
    case "tools/list":
      return reply({
        tools: TOOLS.map(({ name, description, inputSchema }) => ({ name, description, inputSchema })),
      });
    case "tools/call": {
      const tool = TOOL_BY_NAME.get(params && params.name);
      if (!tool) return replyError(-32602, `Unknown tool: ${params && params.name}`);
      try {
        return reply(await tool.run((params && params.arguments) || {}));
      } catch (err) {
        return reply(toolText(`JOAN adapter failed: ${err && err.message ? err.message : String(err)}`, true));
      }
    }
    default:
      if (isNotification) return null;
      return replyError(-32601, `Method not found: ${method}`);
  }
}

// --- stdio transport: newline-delimited JSON-RPC ---------------------------
let buffer = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", async (chunk) => {
  buffer += chunk;
  let idx;
  while ((idx = buffer.indexOf("\n")) >= 0) {
    const line = buffer.slice(0, idx).trim();
    buffer = buffer.slice(idx + 1);
    if (!line) continue;
    let req;
    try {
      req = JSON.parse(line);
    } catch {
      continue; // not JSON: ignore the line, keep the transport alive
    }
    const res = await handle(req);
    if (res) process.stdout.write(JSON.stringify(res) + "\n");
  }
});
process.stdin.on("end", () => process.exit(0));
process.stderr.write(`joan-mcp ready (adapter: ${INTEGRATION_DIR}, doctrine: JOAN judges only)\n`);
