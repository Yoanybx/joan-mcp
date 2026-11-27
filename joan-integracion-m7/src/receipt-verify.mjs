/**
 * Juicio de recibos del lado JOAN — RE-PASADA MOTOR 7 contra la interfaz
 * REAL de D04 (Motor 1), no contra el doble.
 *
 * Formatos con juez hoy:
 *  · MT-BRIDGE-PROOF-1 — delega en verifyBridgeProof real (como en M5).
 *  · MT-ATTESTATION-PROOF-1 — el paquete empresarial que D04 congela:
 *    delega en verifyAttestationProof real de mt-verify, con las anclas
 *    publicadas que aporte el llamante (huella constitucional, hash del
 *    génesis, H(M0)). Sin anclas el veredicto puede ser VALID pero la
 *    atribución será UNANCHORED: el llamante decide qué exige.
 *
 * Todo otro formato se declara NOT_VERIFIABLE: nunca se acepta por
 * confianza. Cuando JOAN tenga su juez Rust (joan-mt-verify), deberá
 * juzgar estos mismos paquetes con CERO divergencias contra este juicio.
 */
import { verifyBridgeProof, verifyAttestationProof } from "../../million-tower/dist/src/mt-verify.js";

export function verifyJoanReceipt(pkg, anchors = undefined) {
  if (!pkg || typeof pkg !== "object") {
    return { verdict: "NOT_VERIFIABLE", kind: null, components: {}, errors: ["El paquete no es un objeto JSON"] };
  }
  if (pkg.format === "MT-BRIDGE-PROOF-1") {
    const r = verifyBridgeProof(pkg);
    return { verdict: r.verdict, kind: "bridge", components: r.components, errors: r.errors };
  }
  if (pkg.format === "MT-ATTESTATION-PROOF-1") {
    const r = verifyAttestationProof(pkg, anchors);
    return {
      verdict: r.verdict,
      kind: "attestation",
      attribution: r.attribution ?? null,
      components: r.components,
      errors: r.errors,
      predicates: r.predicates ?? null,
    };
  }
  return {
    verdict: "NOT_VERIFIABLE",
    kind: typeof pkg.format === "string" ? pkg.format : null,
    components: {},
    errors: [
      `Formato ${JSON.stringify(pkg.format)} sin juez del lado JOAN: ` +
      "no se acepta por confianza",
    ],
  };
}

export function receiptIsFinalValid(judgment) {
  return judgment.verdict === "VALID";
}
