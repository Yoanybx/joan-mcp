/**
 * Inbox idempotente de eventos firmados del lado JOAN (ESPEC §2 C-4).
 *
 * La plataforma entrega MT-WEBHOOK-DELIVERY-1 con entrega al-menos-una-vez:
 * el replay es normal. Reglas (ADV-18 de V2.1):
 *  1. La firma ML-DSA-87 sobre los bytes EXACTOS del cuerpo se verifica con la
 *     función pública real del protocolo (verifyWebhookDelivery) ANTES de
 *     mirar el contenido. Sin firma válida, el evento no existe.
 *  2. La identidad del evento es (event_seq, event_hash) — NO el delivery_id,
 *     que cambia por intento de entrega. Cada evento se APLICA una sola vez;
 *     los replays se absorben como DUPLICATE sin efecto.
 *  3. El conjunto de aplicados persiste en disco: un reinicio no re-aplica.
 *  4. Reproducir nunca ejecuta: la inbox solo registra; los efectos los decide
 *     el caso, sobre eventos aplicados exactamente una vez.
 */
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { verifyWebhookDelivery } from "../../million-tower/dist/src/webhooks.js";

export class WebhookInbox {
  /** @param {{storeFile: string, publicKeyB64: string}} opts */
  constructor({ storeFile, publicKeyB64 }) {
    this.storeFile = storeFile;
    this.publicKeyB64 = publicKeyB64;
    this.applied = new Map(); // key -> {topic, applied_at}
    if (existsSync(storeFile)) {
      const raw = JSON.parse(readFileSync(storeFile, "utf8"));
      for (const [k, v] of Object.entries(raw)) this.applied.set(k, v);
    }
    this.appliedCount = 0;
    this.duplicateCount = 0;
    this.invalidCount = 0;
  }

  persist() {
    mkdirSync(dirname(this.storeFile), { recursive: true });
    writeFileSync(this.storeFile, JSON.stringify(Object.fromEntries(this.applied), null, 2));
  }

  static eventKey(event) {
    return `${event.event_seq}:${event.event_hash}`;
  }

  /**
   * Recibe una entrega cruda.
   * @returns {{status: "APPLIED"|"DUPLICATE"|"INVALID", reason?: string, event?: object}}
   */
  receive(bodyText, signatureB64) {
    if (!verifyWebhookDelivery(bodyText, signatureB64, this.publicKeyB64)) {
      this.invalidCount++;
      return { status: "INVALID", reason: "MT_EVENT_SIGNATURE_INVALID" };
    }
    let envelope;
    try {
      envelope = JSON.parse(bodyText);
    } catch {
      this.invalidCount++;
      return { status: "INVALID", reason: "Cuerpo no es JSON pese a firmar (no debería ocurrir)" };
    }
    if (envelope.format !== "MT-WEBHOOK-DELIVERY-1" || !envelope.event) {
      this.invalidCount++;
      return { status: "INVALID", reason: "Sobre sin formato MT-WEBHOOK-DELIVERY-1 o sin evento" };
    }
    const key = WebhookInbox.eventKey(envelope.event);
    if (this.applied.has(key)) {
      this.duplicateCount++;
      return { status: "DUPLICATE", event: envelope.event };
    }
    this.applied.set(key, { topic: envelope.event.topic, applied_at: new Date().toISOString() });
    this.persist();
    this.appliedCount++;
    return { status: "APPLIED", event: envelope.event };
  }

  hasApplied(event) {
    return this.applied.has(WebhookInbox.eventKey(event));
  }
}
