/**
 * Fase 12 · Eventos del protocolo y webhooks firmados (grupo I, D-25) — TESTNET.
 *
 * Registro de eventos del protocolo con retención de 90 días y entrega
 * webhook firmada ML-DSA-87:
 *  - Cada evento emitido por un punto real del sistema (acuñación, diario,
 *    mercado, sorteos, checkpoints) se persiste con un `event_seq`
 *    monótono; el cursor de reproducción es ese seq en texto.
 *  - `events_replay` devuelve los eventos POSTERIORES al cursor, sin
 *    tocar ningún estado: reproducir no ejecuta nada.
 *  - Un webhook registrado recibe, por cada evento de sus temas, una
 *    entrega: cuerpo canónico JCS `MT-WEBHOOK-DELIVERY-1` (con el evento
 *    y su timestamp dentro del propio cuerpo firmado) y cabecera
 *    `x-mt-signature` con la firma ML-DSA-87 sobre los BYTES EXACTOS del
 *    cuerpo enviado. La clave de firma es una clave dedicada de webhooks
 *    (par ML-DSA-87 propio, solo bajo data/); su clave pública se expone
 *    en el estado para que cualquier receptor verifique sin la empresa.
 *  - `verifyWebhookDelivery(body, signature, publicKey)` es la función
 *    pública del receptor: verifica la firma sobre los bytes recibidos.
 *    Una entrega sin firmar o mal firmada NO verifica — y la batería lo
 *    prueba con una falsificación.
 *  - Entrega al-menos-una-vez: hasta `maxAttempts` intentos por evento y
 *    endpoint; cada intento queda registrado y el estado por endpoint
 *    (entregas, éxitos, fallos, último estado) es consultable.
 *
 * Dinero real: BLOQUEADO. Esto es testnet/simulación.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { canonicalBytes, canonicalize } from "./jcs.js";
import { mtDual1024, ZERO_HASH_1024 } from "./hash.js";
import { generateMlDsa87, signMlDsa87, verifyMlDsa87 } from "./keys.js";
export const WEBHOOK_TOPICS = [
    "brick.minted",
    "brick.transferred",
    "index.updated",
    "index.halted",
    "draw.closed",
    "draw.result",
    "checkpoint.published",
    "usd.settled",
];
export const EVENT_RETENTION_MS = 90 * 24 * 3600 * 1000;
export class WebhookError extends Error {
    code;
    field;
    constructor(code, message, field) {
        super(message);
        this.code = code;
        this.name = "WebhookError";
        if (field !== undefined)
            this.field = field;
    }
}
/** prev_hash de un evento encadenado cuyo predecesor retenido es legado (sin hash). */
export const EVENT_LEGACY_PREV = "MT-EVENT-LEGACY-PREV";
const EVENT_HASH_DOMAIN = "MT-EVENT-1";
/** Hash de integridad de un evento: MT-DUAL-1024(dominio ‖ JCS(núcleo)). */
export function computeEventHash(ev) {
    return mtDual1024(canonicalBytes({
        event_seq: ev.event_seq,
        event_id: ev.event_id,
        topic: ev.topic,
        timestamp_ms: ev.timestamp_ms,
        data: ev.data,
        prev_hash: ev.prev_hash ?? null,
    }), EVENT_HASH_DOMAIN);
}
/**
 * Verifica la cadena de integridad del registro retenido: recomputa cada
 * hash desde el contenido y comprueba el enlace con el anterior. Detecta
 * contenido alterado, eventos insertados o sustituidos, reordenaciones,
 * borrado intermedio, borrado de cola (vía next_seq) y borrado del
 * primer evento retenido: el primer evento con hash debe anclar en el
 * suelo de poda registrado (`floorHash`) o, si no hay suelo, en
 * ZERO_HASH_1024 (el inicio de la cadena). Los eventos legados cuentan
 * aparte: mientras el registro tenga SOLO legados, el estado es
 * LEGACY_UNVERIFIABLE — nunca OK.
 */
export function verifyEventLogIntegrity(events, nextSeq, floorHash) {
    let checked = 0;
    let legacy = 0;
    let prevHash = null;
    let prevWasLegacy = false;
    const broken = (seq, detail) => ({
        status: "BROKEN",
        checked,
        legacy,
        first_bad_seq: seq,
        detail,
    });
    for (const ev of events) {
        if (typeof ev.event_hash !== "string" || typeof ev.prev_hash !== "string") {
            legacy++;
            prevHash = null;
            prevWasLegacy = true;
            continue;
        }
        if (prevHash !== null && ev.prev_hash !== prevHash) {
            return broken(ev.event_seq, `El evento ${ev.event_seq} no encadena con el hash del evento anterior (sustitución, inserción o reordenación)`);
        }
        if (prevHash === null && prevWasLegacy && ev.prev_hash !== EVENT_LEGACY_PREV) {
            return broken(ev.event_seq, `El evento ${ev.event_seq} sigue a eventos legados pero no ancla en EVENT_LEGACY_PREV`);
        }
        if (prevHash === null && !prevWasLegacy) {
            // Primer evento retenido con hash: su ancla es exigible (AUD-04).
            const anchor = floorHash ?? ZERO_HASH_1024;
            if (ev.prev_hash !== anchor) {
                return broken(ev.event_seq, floorHash !== undefined
                    ? `El primer evento retenido (${ev.event_seq}) no ancla en el suelo de poda registrado: falta un evento al principio o el registro fue reescrito`
                    : `El primer evento retenido (${ev.event_seq}) no ancla en el inicio de la cadena (ZERO) y no hay suelo de poda registrado: falta el evento inicial o el registro fue podado por código anterior a la fase 14`);
            }
        }
        if (computeEventHash(ev) !== ev.event_hash) {
            return broken(ev.event_seq, `El hash del evento ${ev.event_seq} no se reproduce desde su contenido: el contenido fue alterado`);
        }
        checked++;
        prevHash = ev.event_hash;
        prevWasLegacy = false;
    }
    if (nextSeq !== undefined && events.length > 0) {
        const last = events[events.length - 1];
        if (last.event_seq !== nextSeq - 1) {
            return broken(last.event_seq + 1, `El registro retenido termina en el seq ${last.event_seq} pero next_seq es ${nextSeq}: faltan eventos al final (borrado de cola)`);
        }
    }
    if (checked === 0) {
        return {
            status: "LEGACY_UNVERIFIABLE",
            checked,
            legacy,
            first_bad_seq: null,
            detail: "Ningún evento retenido lleva hash de integridad (registro anterior a la fase 14): su contenido no es verificable",
        };
    }
    return {
        status: "OK",
        checked,
        legacy,
        first_bad_seq: null,
        detail: legacy > 0
            ? `Cadena íntegra en los ${checked} eventos con hash; ${legacy} eventos legados sin hash quedan fuera de la verificación`
            : `Cadena íntegra: ${checked} eventos verificados por contenido y enlace`,
    };
}
async function defaultDeliver(url, bodyText, headers) {
    try {
        const res = await fetch(url, {
            method: "POST",
            headers,
            body: bodyText,
            signal: AbortSignal.timeout(5_000),
        });
        return { ok: res.ok, status: res.status, ...(res.ok ? {} : { error: `HTTP ${res.status}` }) };
    }
    catch (e) {
        return { ok: false, error: e instanceof Error ? e.message : String(e) };
    }
}
/** Verificación del lado del receptor: firma ML-DSA-87 sobre los bytes exactos del cuerpo. */
export function verifyWebhookDelivery(body, signatureB64, publicKeyB64) {
    if (typeof signatureB64 !== "string" || signatureB64.length === 0)
        return false;
    const bytes = typeof body === "string" ? Buffer.from(body, "utf8") : Buffer.from(body);
    return verifyMlDsa87(publicKeyB64, bytes, Buffer.from(signatureB64, "base64"));
}
const MAX_DELIVERY_RECORDS = 1000;
export class WebhookService {
    dir;
    clockFn;
    deliverFn;
    maxAttempts;
    keypair;
    events;
    endpoints;
    subscriptions;
    deliveries;
    constructor(opts) {
        this.dir = opts.dir;
        mkdirSync(this.dir, { recursive: true });
        this.clockFn = opts.clock ?? (() => Date.now());
        this.deliverFn = opts.deliver ?? defaultDeliver;
        this.maxAttempts = opts.maxAttempts ?? 3;
        this.keypair = this.loadOrCreateKey();
        this.events = this.load(this.eventsPath, { format: "MT-EVENT-LOG-1", next_seq: 1, events: [] });
        this.endpoints = this.load(this.endpointsPath, { format: "MT-WEBHOOK-ENDPOINTS-1", endpoints: [] });
        this.subscriptions = this.load(this.subscriptionsPath, { format: "MT-EVENT-SUBSCRIPTIONS-1", subscriptions: {} });
        this.deliveries = this.load(this.deliveriesPath, { format: "MT-WEBHOOK-DELIVERIES-1", deliveries: [] });
    }
    get keyPath() { return join(this.dir, "signing-key.json"); }
    get eventsPath() { return join(this.dir, "events.json"); }
    get endpointsPath() { return join(this.dir, "endpoints.json"); }
    get subscriptionsPath() { return join(this.dir, "subscriptions.json"); }
    get deliveriesPath() { return join(this.dir, "deliveries.json"); }
    load(path, fallback) {
        if (!existsSync(path))
            return fallback;
        return JSON.parse(readFileSync(path, "utf8"));
    }
    save(path, value) {
        writeFileSync(path, JSON.stringify(value, null, 2) + "\n", "utf8");
    }
    loadOrCreateKey() {
        if (existsSync(this.keyPath)) {
            const parsed = JSON.parse(readFileSync(this.keyPath, "utf8"));
            if (parsed.format !== "MT-WEBHOOK-SIGNING-KEY-1" || parsed.algorithm !== "ML-DSA-87") {
                throw new Error(`Fichero de clave de firma de webhooks no reconocido: ${this.keyPath}`);
            }
            return parsed.keypair;
        }
        const file = {
            format: "MT-WEBHOOK-SIGNING-KEY-1",
            warning: "TESTNET: clave dedicada de firma de entregas webhook (ML-DSA-87). Vive solo bajo data/; su clave pública se publica para que los receptores verifiquen sin la empresa.",
            algorithm: "ML-DSA-87",
            keypair: generateMlDsa87(),
        };
        writeFileSync(this.keyPath, JSON.stringify(file, null, 2) + "\n", "utf8");
        return file.keypair;
    }
    /** Clave pública con la que cualquier receptor verifica las entregas. */
    signingPublicKey() { return this.keypair.publicKey; }
    nowMs() { return this.clockFn(); }
    // — Suscripciones ————————————————————————————————————————————————————————————
    subscribe(agentId, topics) {
        if (!Array.isArray(topics) || topics.length === 0 || topics.some((t) => typeof t !== "string")) {
            throw new WebhookError("VALIDATION_FAILED", "topics debe ser un array no vacío de temas", "topics");
        }
        for (const t of topics) {
            if (!WEBHOOK_TOPICS.includes(t)) {
                throw new WebhookError("EVENT_TOPIC_NOT_ALLOWED", `Tema de evento desconocido: ${t}. Temas: ${WEBHOOK_TOPICS.join(", ")}`, "topics");
            }
        }
        const unique = [...new Set(topics)];
        const existing = this.subscriptions.subscriptions[agentId];
        const record = {
            subscription_id: existing?.subscription_id ?? `SUB-${randomBytes(6).toString("hex").toUpperCase()}`,
            topics: unique,
            created_at_ms: existing?.created_at_ms ?? this.clockFn(),
        };
        this.subscriptions.subscriptions[agentId] = record;
        this.save(this.subscriptionsPath, this.subscriptions);
        return { subscription_id: record.subscription_id, topics: record.topics };
    }
    topicsOf(agentId) {
        return this.subscriptions.subscriptions[agentId]?.topics ?? null;
    }
    // — Endpoints ————————————————————————————————————————————————————————————————
    registerEndpoint(agentId, url, topics) {
        if (typeof url !== "string" || url.length === 0) {
            throw new WebhookError("WEBHOOK_URL_INVALID", "La URL del webhook debe ser una cadena no vacía", "url");
        }
        let parsed;
        try {
            parsed = new URL(url);
        }
        catch {
            throw new WebhookError("WEBHOOK_URL_INVALID", `URL de webhook inválida: ${url}`, "url");
        }
        if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
            throw new WebhookError("WEBHOOK_URL_INVALID", `La URL del webhook debe ser http(s): ${url}`, "url");
        }
        const effectiveTopics = topics ?? this.topicsOf(agentId) ?? [...WEBHOOK_TOPICS];
        const endpoint = {
            endpoint_id: `WH-${randomBytes(6).toString("hex").toUpperCase()}`,
            agent_id: agentId,
            url,
            topics: effectiveTopics,
            created_at_ms: this.clockFn(),
            deliveries: 0,
            delivered: 0,
            failed: 0,
            last_status: null,
            last_event_seq: 0,
        };
        this.endpoints.endpoints.push(endpoint);
        this.save(this.endpointsPath, this.endpoints);
        return endpoint;
    }
    endpointsOf(agentId) {
        return this.endpoints.endpoints.filter((e) => agentId === undefined || e.agent_id === agentId);
    }
    deliveriesOf(endpointId) {
        return this.deliveries.deliveries.filter((d) => endpointId === undefined || d.endpoint_id === endpointId);
    }
    // — Emisión ——————————————————————————————————————————————————————————————————
    pruneRetention() {
        const cutoff = this.clockFn() - EVENT_RETENTION_MS;
        const before = this.events.events.length;
        const dropped = this.events.events.filter((e) => e.timestamp_ms < cutoff);
        this.events.events = this.events.events.filter((e) => e.timestamp_ms >= cutoff);
        if (this.events.events.length !== before) {
            // Suelo de poda (AUD-04): el último evento podado queda como ancla
            // exigible del primer evento retenido.
            const lastDropped = dropped[dropped.length - 1];
            if (lastDropped) {
                this.events.floor_hash = typeof lastDropped.event_hash === "string" ? lastDropped.event_hash : EVENT_LEGACY_PREV;
            }
            this.save(this.eventsPath, this.events);
        }
    }
    /**
     * Emite un evento desde un punto real del sistema: lo persiste en el
     * registro (con la retención de 90 días aplicada) y lo entrega a los
     * endpoints suscritos a su tema, con reintentos. Nunca lanza por un
     * fallo de entrega: el fallo queda registrado por endpoint.
     */
    async emit(topic, data) {
        if (!WEBHOOK_TOPICS.includes(topic)) {
            throw new WebhookError("EVENT_TOPIC_NOT_ALLOWED", `Tema de evento desconocido: ${topic}`);
        }
        this.pruneRetention();
        const seq = this.events.next_seq;
        const prev = this.events.events[this.events.events.length - 1];
        const event = {
            event_seq: seq,
            event_id: String(seq),
            topic,
            timestamp_ms: this.clockFn(),
            data,
            // Cadena de integridad AUD-04: cada evento nuevo nace encadenado.
            // Si la poda vació el registro, encadena con el suelo de poda.
            prev_hash: !prev ? (this.events.floor_hash ?? ZERO_HASH_1024) : typeof prev.event_hash === "string" ? prev.event_hash : EVENT_LEGACY_PREV,
        };
        event.event_hash = computeEventHash(event);
        this.events.events.push(event);
        this.events.next_seq = seq + 1;
        this.save(this.eventsPath, this.events);
        for (const endpoint of this.endpoints.endpoints) {
            if (!endpoint.topics.includes(topic))
                continue;
            await this.deliver(endpoint, event);
        }
        return event;
    }
    async deliver(endpoint, event) {
        const deliveryId = `DLV-${randomBytes(6).toString("hex").toUpperCase()}`;
        const envelope = {
            format: "MT-WEBHOOK-DELIVERY-1",
            delivery_id: deliveryId,
            endpoint_id: endpoint.endpoint_id,
            timestamp_ms: this.clockFn(),
            event,
        };
        const bodyText = canonicalize(envelope);
        const signature = signMlDsa87(this.keypair.privateKey, Buffer.from(bodyText, "utf8")).toString("base64");
        const headers = {
            "content-type": "application/json",
            "x-mt-signature": signature,
            "x-mt-timestamp": String(envelope.timestamp_ms),
            "x-mt-delivery-id": deliveryId,
            "x-mt-event-topic": event.topic,
        };
        let attempts = 0;
        let ok = false;
        let lastError = null;
        while (attempts < this.maxAttempts && !ok) {
            attempts++;
            const res = await this.deliverFn(endpoint.url, bodyText, headers);
            ok = res.ok;
            if (!ok)
                lastError = res.error ?? `HTTP ${res.status ?? "?"}`;
        }
        endpoint.deliveries++;
        if (ok)
            endpoint.delivered++;
        else
            endpoint.failed++;
        endpoint.last_status = ok ? "DELIVERED" : "FAILED";
        endpoint.last_event_seq = event.event_seq;
        this.save(this.endpointsPath, this.endpoints);
        const record = {
            delivery_id: deliveryId,
            endpoint_id: endpoint.endpoint_id,
            event_seq: event.event_seq,
            topic: event.topic,
            attempts,
            status: ok ? "DELIVERED" : "FAILED",
            last_error: ok ? null : lastError,
            timestamp_ms: this.clockFn(),
        };
        this.deliveries.deliveries.push(record);
        if (this.deliveries.deliveries.length > MAX_DELIVERY_RECORDS) {
            this.deliveries.deliveries = this.deliveries.deliveries.slice(-MAX_DELIVERY_RECORDS);
        }
        this.save(this.deliveriesPath, this.deliveries);
        return record;
    }
    // — Lectura / reproducción ———————————————————————————————————————————————————
    /** Eventos visibles para un agente: los de sus temas si está suscrito; si no, todos. */
    visibleFor(agentId) {
        const topics = this.topicsOf(agentId);
        return this.events.events.filter((e) => topics === null || topics.includes(e.topic));
    }
    /** Integridad del registro completo retenido (no solo de la vista del agente). */
    eventLogIntegrity() {
        return verifyEventLogIntegrity(this.events.events, this.events.next_seq, this.events.floor_hash);
    }
    /** Últimos `limit` eventos visibles para el agente (en orden cronológico). */
    list(agentId, limit = 50) {
        this.pruneRetention();
        const visible = this.visibleFor(agentId);
        const slice = visible.slice(-Math.max(1, Math.min(limit, 500)));
        return {
            events: slice,
            next_cursor: slice.length > 0 ? slice[slice.length - 1].event_id : null,
            integrity: this.eventLogIntegrity(),
        };
    }
    /**
     * Reproducción desde un cursor: eventos con seq > cursor, en orden.
     * Es SOLO lectura: no cambia estado ni vuelve a entregar webhooks.
     */
    replay(agentId, cursor) {
        this.pruneRetention();
        let from = 0;
        if (cursor !== undefined && cursor !== "") {
            const n = Number(cursor);
            if (!Number.isSafeInteger(n) || n < 0) {
                throw new WebhookError("VALIDATION_FAILED", `Cursor de reproducción inválido: ${cursor}`, "cursor");
            }
            from = n;
        }
        const events = this.visibleFor(agentId).filter((e) => e.event_seq > from);
        return {
            events,
            next_cursor: events.length > 0 ? events[events.length - 1].event_id : String(from),
            from_cursor: String(from),
            integrity: this.eventLogIntegrity(),
        };
    }
    get lastEventSeq() {
        return this.events.next_seq - 1;
    }
}
