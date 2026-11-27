/**
 * Puerta de permiso del lado JOAN (ESPEC §2 C-1, V2.1 §14.6).
 *
 * Valida el PolicyPermit empresarial ANTES de ejecutar: esquema cerrado,
 * decisión ALLOW, vigencia, ligadura exacta a (destinatario, importe, moneda,
 * proveedor) y consumo de un solo uso ANTES de someter el pago (ni un fallo
 * posterior resucita el permiso — misma doctrina que el nonce D-19).
 * La firma del servicio se verifica a través del verificador inyectado:
 * hoy un doble; con C2, la clave del servicio empresarial.
 */
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

export const PERMIT_FIELDS = [
  "format", "reservation_id", "tenant_id", "agent_id", "recipient",
  "amount_minor", "currency", "provider", "single_use",
  "issued_at", "expires_at", "policy_version", "decision", "service_signature",
];

export class PermitError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

export class PermitGate {
  /**
   * @param {{storeFile: string, verifyServiceSignature: (permit: object) => boolean, now?: () => number}} opts
   */
  constructor({ storeFile, verifyServiceSignature, now = () => Date.now() }) {
    this.storeFile = storeFile;
    this.verifyServiceSignature = verifyServiceSignature;
    this.now = now;
    this.consumed = new Set();
    if (existsSync(storeFile)) {
      for (const id of JSON.parse(readFileSync(storeFile, "utf8"))) this.consumed.add(id);
    }
  }

  persist() {
    mkdirSync(dirname(this.storeFile), { recursive: true });
    writeFileSync(this.storeFile, JSON.stringify([...this.consumed], null, 2));
  }

  /** Validación estructural y de ligadura. NO consume: eso es assertUsableAndConsume. */
  validate(permit, expected) {
    if (!permit || typeof permit !== "object") {
      throw new PermitError("MT_CAPABILITY_DENIED", "Sin objeto permiso no hay autorización");
    }
    for (const k of Object.keys(permit)) {
      if (!PERMIT_FIELDS.includes(k)) {
        throw new PermitError("MT_CAPABILITY_DENIED", `Campo fuera de esquema en el permiso: ${k}`);
      }
    }
    if (permit.format !== "MT-POLICY-PERMIT-1") {
      throw new PermitError("MT_CAPABILITY_DENIED", `Formato de permiso no reconocido: ${permit.format}`);
    }
    if (permit.decision !== "ALLOW") {
      throw new PermitError("MT_CAPABILITY_DENIED", `Decisión del permiso: ${permit.decision}`);
    }
    if (permit.single_use !== true) {
      throw new PermitError("MT_CAPABILITY_DENIED", "El permiso debe ser de un solo uso");
    }
    if (!this.verifyServiceSignature(permit)) {
      throw new PermitError("AGENT_SIGNATURE_INVALID", "Firma del servicio inválida en el permiso");
    }
    const exp = Date.parse(permit.expires_at);
    if (!Number.isFinite(exp) || exp <= this.now()) {
      throw new PermitError("MT_CAPABILITY_DENIED", "Permiso expirado");
    }
    if (permit.recipient !== expected.recipient || permit.provider !== expected.provider) {
      throw new PermitError("MT_CAPABILITY_DENIED", "El permiso no está ligado a este destinatario/proveedor");
    }
    if (permit.currency !== expected.currency) {
      throw new PermitError("MT_CAPABILITY_DENIED", "Moneda del permiso distinta de la operación");
    }
    const amount = BigInt(permit.amount_minor);
    const wanted = BigInt(expected.amountMinor);
    if (amount < wanted) {
      throw new PermitError("MT_BUDGET_EXCEEDED", `Permiso ${amount} < operación ${wanted} (unidades menores)`);
    }
    if (amount !== wanted) {
      throw new PermitError("MT_CAPABILITY_DENIED", "El importe del permiso debe ser EXACTO al de la operación (ligadura por digest)");
    }
    return true;
  }

  /** Consume el permiso (single_use) tras validar. El consumo precede a la ejecución. */
  assertUsableAndConsume(permit, expected) {
    this.validate(permit, expected);
    if (this.consumed.has(permit.reservation_id)) {
      throw new PermitError("MT_PERMIT_ALREADY_CONSUMED", `Permiso ya consumido: ${permit.reservation_id}`);
    }
    this.consumed.add(permit.reservation_id);
    this.persist();
    return true;
  }

  isConsumed(reservationId) {
    return this.consumed.has(reservationId);
  }
}
