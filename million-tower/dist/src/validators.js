/**
 * Fase 4 · Consenso BFT de testnet — registro de validadores y finalidad 3-de-4.
 *
 * Modelo cerrado (D-02 de la spec V1.2, llevado a testnet):
 *  - 4 validadores con identidades y pares ML-DSA-87 INDEPENDIENTES. Custodia
 *    separada: cada validador firma solo con su clave; el conjunto guarda las
 *    claves privadas en memoria cargadas desde data/validators/ (un fichero por
 *    validador) y el manifiesto público contiene SOLO claves públicas.
 *  - Una transición (bloque de acuñación u operación del diario) es FINAL solo
 *    con >= 3 firmas válidas de validadores DISTINTOS sobre los bytes canónicos
 *    exactos de la transición (chain_id, tipo, secuencia, estado previo y
 *    huella de la transición). La firma repetida de un mismo validador cuenta
 *    una vez. Dos validadores NO finalizan nada.
 *  - Bloqueo de voto por secuencia: un validador no firma dos transiciones
 *    distintas para la misma (cadena, tipo, secuencia). El segundo intento se
 *    rechaza y queda EVIDENCIA en el registro de equívocos (VoteLedger).
 *  - Custodia duradera (MT-VOTELEDGER-2, ronda 6): la firma de voto solo se
 *    emite a través de DurableVoteLedger (src/voteledger.ts), que persiste
 *    el compromiso de voto (append-only encadenado, con fsync) ANTES de
 *    firmar y persiste la firma ANTES de entregarla. El bloqueo por
 *    secuencia sobrevive a reinicios de proceso; la corrupción o el
 *    rollback del registro detienen la firma (fail-closed). El VoteLedger
 *    en memoria queda como espejo de evidencia y puerta de presentación
 *    de votos externos (FinalityCollector.presentVote).
 *  - Testigo externo y recuperación (R7-VOTE-RECOVERY): cada compromiso
 *    duradero deja además una referencia de continuidad en el testigo
 *    externo de la identidad, fuera de la copia restaurable; al abrir, la
 *    custodia emite su VoteLedgerRecoveryProof y un rollback a un estado
 *    íntegro pero antiguo —o una copia divergente de la misma identidad—
 *    queda en SIGNING_DISABLED / RECOVERY_REQUIRED, sin firmar nada.
 *    La compactación del registro sigue MT-WAL-COMPACT-1.
 *
 * Esto es TESTNET: las claves no protegen valor real. Dinero real: BLOQUEADO.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { canonicalBytes, canonicalize } from "./jcs.js";
import { mtDual1024 } from "./hash.js";
import { generateMlDsa87, signMlDsa87, verifyMlDsa87 } from "./keys.js";
import { DurableVoteLedger, VoteLedgerCustodyError, validatorSetEpoch, voteLedgerPath, } from "./voteledger.js";
import { firstUnknownField, schemaFieldNotAllowedMessage, FINALITY_CERTIFICATE_FIELDS, TRANSITION_DESCRIPTOR_FIELDS, VOTE_FIELDS, } from "./schema.js";
import { KeystoreError, decodeValidatorKeyFile, keyCustodyFor, } from "./keystore.js";
export const VALIDATOR_COUNT = 4;
export const FINALITY_QUORUM = 3;
export const VALIDATOR_IDS = [
    "validator-1",
    "validator-2",
    "validator-3",
    "validator-4",
];
/* =====================================================================
 * MANIFIESTO ANCLADO MT-VALIDATOR-MANIFEST-2 (FUZZ-1 · opción C en
 * forma fuerte, adjudicación de la casa).
 *
 * El manifiesto V1 era una tabla de claves públicas SIN autenticar:
 * la carga la contrastaba contra los ficheros (contraste A) y nada
 * ligaba la tabla misma — quien reescribía tabla y ficheros a la vez
 * pasaba la carga con un conjunto íntegro de claves ajenas (KS-1 del
 * fuzzing M3). El ancla mueve la raíz de la identidad de la
 * POSICIÓN (el directorio) al CONTENIDO verificado en la carga:
 *
 *  - cada entrada registra su `key_fingerprint` =
 *    MT-DUAL-1024(dominio MT-VALIDATOR-KEY-FINGERPRINT-1 ∥
 *    JCS({validator_id, public_key})), recomputada en la carga sobre
 *    {entry.validator_id, pública DERIVADA del fichero} (REM-FZ-01);
 *  - el manifiesto registra su `manifest_fingerprint` =
 *    MT-DUAL-1024(dominio MT-VALIDATOR-MANIFEST-2 ∥ JCS(núcleo)),
 *    con el núcleo {format, chain_id, quorum, validators:[…]} — el
 *    mismo patrón de canonicalManifestHash de la cadena canónica,
 *    que NO se toca —;
 *  - cada validador ATESTIGUA el manifiesto con su propia clave
 *    ML-DSA-87 sobre los bytes canónicos de {domain:
 *    "MT-VALIDATOR-MANIFEST-ATTEST-1", chain_id,
 *    manifest_fingerprint, validator_id, public_key,
 *    key_fingerprint}: la atestación liga la huella ENTERA del
 *    manifiesto y la entrada PROPIA — una entrada transplantada de
 *    otro manifiesto no verifica en este (anti-transplante).
 *
 * La verificación sigue el orden fail-closed de la adjudicación
 * (§4.2) en UNA ÚNICA función compartida —
 * verifyAnchoredValidatorManifest — que invocan las dos puertas que
 * consumen la tabla (ValidatorSet.loadOrCreate y ValidatorNet,
 * incluido el proceso nodo): (1) parseo y comprobaciones vigentes
 * (formato, chain_id esperada, conteo, quórum contra las constantes
 * de código); (2) recomputación de manifest_fingerprint; (3)
 * atestación de CADA entrada verificada contra su clave pública —
 * las cuatro, sin quórum parcial —; (4) por cada fichero de clave
 * (solo loadOrCreate, que custodia el material): decode con todas
 * las reglas KS, pública derivada == pública de la entrada,
 * validator_id decodificado == entrada, y huella recomputada ==
 * huella registrada; (5) los fallos de 2–3 se tipan
 * KEYSTORE_MANIFEST_UNVERIFIED y los de 4 (huella o contraste)
 * KEYSTORE_KEY_ANCHOR_MISMATCH — nunca un Error genérico, nunca
 * tragados —.
 *
 * La FIRMA solo ocurre en la creación del conjunto y en la
 * migración gobernada, con las claves en memoria; la carga verifica,
 * jamás firma. El manifiesto legado MT-VALIDATOR-MANIFEST-1 ya NO
 * entra por la puerta de carga (rechazo tipado): su única vía es la
 * migración gobernada registrada (scripts/migrate-validator-
 * manifest.ts), que lee una vez bajo el contraste A transitorio,
 * reescribe SOLO manifest.json y deja los ficheros de clave byte a
 * byte intactos. El contraste A como raíz queda así EXPIRADO.
 *
 * Lo que el conjunto EXPONE sigue siendo la proyección operacional
 * V1 ({format: "MT-VALIDATOR-MANIFEST-1", chain_id, quorum,
 * validators:[{validator_id, public_key}]}): los consumidores
 * operacionales (certificados, época del conjunto, verificador) no
 * cambian de forma ni de época — la época se deriva de la
 * proyección, exactamente como antes —. El manifiesto V2 es el
 * formato de DIRECTORIO y el artefacto de verificación en la carga;
 * sus campos extra nunca se filtran a la forma operacional.
 *
 * ALCANCE DECLARADO del ancla (fallo O1 de la adjudicación — ningún
 * texto puede reclamar más): (1) no defiende contra la SUSTITUCIÓN
 * TOTAL del directorio con claves KEY-1: un manifiesto forjado puede
 * re-atestiguarse con las privadas en claro; la defensa ahí es
 * KEY-2 y la custodia del directorio; (2) es AUTO-atestación, no una
 * raíz externa de corrección del conjunto original (esa la aportan
 * la cadena de manifiestos y el bootstrap publicado); (3) el decode
 * aislado de un fichero sigue sin opinar sobre identidad: sus
 * consumidores heredan este límite y deben decirlo.
 * ===================================================================== */
export const VALIDATOR_MANIFEST_ANCHORED_FORMAT = "MT-VALIDATOR-MANIFEST-2";
/** Dominio MT-DUAL-1024 de la huella por entrada (id + pública). */
export const VALIDATOR_KEY_FINGERPRINT_DOMAIN = "MT-VALIDATOR-KEY-FINGERPRINT-1";
/** Dominio MT-DUAL-1024 de la huella del manifiesto anclado. */
export const VALIDATOR_MANIFEST_FINGERPRINT_DOMAIN = "MT-VALIDATOR-MANIFEST-2";
/** Dominio de las atestaciones ML-DSA-87 del manifiesto anclado. */
export const VALIDATOR_MANIFEST_ATTEST_DOMAIN = "MT-VALIDATOR-MANIFEST-ATTEST-1";
/** Huella de una entrada: liga (validator_id, clave pública) y nada más. */
export function validatorKeyFingerprint(validatorId, publicKey) {
    return mtDual1024(canonicalBytes({ public_key: publicKey, validator_id: validatorId }), VALIDATOR_KEY_FINGERPRINT_DOMAIN);
}
/** El núcleo que la huella del manifiesto cubre (patrón de manifestCore). */
function anchoredManifestCore(m) {
    return {
        format: VALIDATOR_MANIFEST_ANCHORED_FORMAT,
        chain_id: m.chain_id,
        quorum: m.quorum,
        validators: m.validators.map((v) => ({
            key_fingerprint: v.key_fingerprint,
            public_key: v.public_key,
            validator_id: v.validator_id,
        })),
    };
}
/** Huella del manifiesto anclado sobre su núcleo canónico. */
export function anchoredManifestFingerprint(m) {
    return mtDual1024(canonicalBytes(anchoredManifestCore(m)), VALIDATOR_MANIFEST_FINGERPRINT_DOMAIN);
}
/**
 * Los bytes que cada validador firma al atestiguar: ligan la huella
 * ENTERA del manifiesto y la entrada PROPIA del firmante (su id, su
 * pública y su huella de entrada) — por eso una atestación no se
 * puede transplantar a otro manifiesto ni a otra entrada.
 */
export function manifestAttestationBytes(args) {
    return canonicalBytes({
        chain_id: args.chain_id,
        domain: VALIDATOR_MANIFEST_ATTEST_DOMAIN,
        key_fingerprint: args.entry.key_fingerprint,
        manifest_fingerprint: args.manifest_fingerprint,
        public_key: args.entry.public_key,
        validator_id: args.entry.validator_id,
    });
}
/**
 * Construye el manifiesto anclado de un conjunto cuyas claves están
 * EN MEMORIA: calcula las huellas y recoge la atestación de cada
 * validador. SOLO se invoca en la creación del conjunto y en la
 * migración gobernada — la firma no ocurre en ninguna otra ruta —.
 */
export function buildAnchoredValidatorManifest(args) {
    const validators = args.keys.map((k) => ({
        validator_id: k.validator_id,
        public_key: k.public_key,
        key_fingerprint: validatorKeyFingerprint(k.validator_id, k.public_key),
    }));
    const manifest_fingerprint = anchoredManifestFingerprint({
        chain_id: args.chainId,
        quorum: FINALITY_QUORUM,
        validators,
    });
    const byId = new Map(validators.map((v) => [v.validator_id, v]));
    const attestations = args.keys.map((k) => ({
        validator_id: k.validator_id,
        signature: signMlDsa87(k.private_key, manifestAttestationBytes({
            chain_id: args.chainId,
            manifest_fingerprint,
            entry: byId.get(k.validator_id),
        })).toString("base64"),
    }));
    return {
        format: VALIDATOR_MANIFEST_ANCHORED_FORMAT,
        chain_id: args.chainId,
        quorum: FINALITY_QUORUM,
        validators,
        manifest_fingerprint,
        attestations,
    };
}
/**
 * LA verificación del ancla (FUZZ-1 · REM-FZ-02): la única función
 * que lee una tabla de validadores, compartida por
 * ValidatorSet.loadOrCreate y por ValidatorNet (arranque del
 * coordinador y proceso nodo). Ejecuta los pasos 1–3 del orden de la
 * adjudicación; el paso 4 (contra los ficheros de clave) es
 * verifyValidatorKeyFilesAgainstManifest. Todo fallo de esta función
 * es un KeystoreError KEYSTORE_MANIFEST_UNVERIFIED: un manifiesto
 * que no verifica NO es un manifiesto con matices — no entra —.
 * Los campos extraños del objeto se ignoran sin efecto: el objeto
 * devuelto se reconstruye SOLO con los campos del inventario
 * (REM-FZ-04) y ningún consumidor ve otra cosa.
 */
export function verifyAnchoredValidatorManifest(raw, expectedChainId) {
    const unverified = (message) => new KeystoreError("KEYSTORE_MANIFEST_UNVERIFIED", message);
    if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
        throw unverified("El manifiesto de validadores no es un objeto JSON: no verifica");
    }
    const m = raw;
    // Paso 1 — formato, cadena y constantes de código. El marcador
    // legado MT-VALIDATOR-MANIFEST-1 muere en esta misma comprobación:
    // tras la entrada en vigor del ancla, cargar sin ancla es un
    // rechazo tipado, no una ruta.
    if (m.format !== VALIDATOR_MANIFEST_ANCHORED_FORMAT) {
        throw unverified(`El manifiesto no es un ${VALIDATOR_MANIFEST_ANCHORED_FORMAT} verificado (declara ${String(m.format)}): la carga sin ancla quedó retirada — los conjuntos legados entran solo por la migración gobernada registrada`);
    }
    if (typeof m.chain_id !== "string" || m.chain_id.length === 0) {
        throw unverified("El manifiesto anclado no declara chain_id");
    }
    if (expectedChainId !== undefined && m.chain_id !== expectedChainId) {
        throw unverified(`El manifiesto anclado es de otra cadena (${m.chain_id} != ${expectedChainId})`);
    }
    if (m.quorum !== FINALITY_QUORUM) {
        throw unverified(`El manifiesto anclado no declara el quórum fijado por el código (${FINALITY_QUORUM})`);
    }
    if (!Array.isArray(m.validators) || m.validators.length !== VALIDATOR_COUNT) {
        throw unverified(`El manifiesto anclado no declara exactamente ${VALIDATOR_COUNT} validadores`);
    }
    const seen = new Set();
    const entries = [];
    for (const v of m.validators) {
        if (v === null || typeof v !== "object" || Array.isArray(v)) {
            throw unverified("Una entrada del manifiesto anclado no es un objeto");
        }
        const e = v;
        if (typeof e.validator_id !== "string" ||
            typeof e.public_key !== "string" ||
            typeof e.key_fingerprint !== "string") {
            throw unverified("Una entrada del manifiesto anclado está incompleta (validator_id/public_key/key_fingerprint)");
        }
        if (seen.has(e.validator_id)) {
            throw unverified(`El manifiesto anclado repite al validador ${e.validator_id}`);
        }
        seen.add(e.validator_id);
        entries.push({
            validator_id: e.validator_id,
            public_key: e.public_key,
            key_fingerprint: e.key_fingerprint,
        });
    }
    // Paso 2 — la huella del manifiesto recomputa sobre la tabla recibida.
    if (typeof m.manifest_fingerprint !== "string") {
        throw unverified("El manifiesto anclado no trae manifest_fingerprint");
    }
    const recomputed = anchoredManifestFingerprint({
        chain_id: m.chain_id,
        quorum: FINALITY_QUORUM,
        validators: entries,
    });
    if (recomputed !== m.manifest_fingerprint) {
        throw unverified("La huella del manifiesto anclado no recomputa sobre su tabla: la tabla no es la atestiguada");
    }
    // Paso 3 — la atestación de CADA entrada, contra su propia clave.
    if (!Array.isArray(m.attestations)) {
        throw unverified("El manifiesto anclado no trae atestaciones: un manifiesto sin atestiguar no verifica");
    }
    const attBy = new Map();
    for (const a of m.attestations) {
        if (a === null || typeof a !== "object" || Array.isArray(a)) {
            throw unverified("Una atestación del manifiesto anclado no es un objeto");
        }
        const at = a;
        if (typeof at.validator_id !== "string" || typeof at.signature !== "string") {
            throw unverified("Una atestación del manifiesto anclado está incompleta (validator_id/signature)");
        }
        if (attBy.has(at.validator_id)) {
            throw unverified(`El manifiesto anclado trae dos atestaciones de ${at.validator_id}`);
        }
        attBy.set(at.validator_id, at.signature);
    }
    for (const entry of entries) {
        const signature = attBy.get(entry.validator_id);
        if (signature === undefined) {
            throw unverified(`Falta la atestación de ${entry.validator_id}: sin las ${VALIDATOR_COUNT} no hay manifiesto verificado`);
        }
        let ok = false;
        try {
            ok = verifyMlDsa87(entry.public_key, manifestAttestationBytes({
                chain_id: m.chain_id,
                manifest_fingerprint: m.manifest_fingerprint,
                entry,
            }), Buffer.from(signature, "base64"));
        }
        catch {
            ok = false;
        }
        if (!ok) {
            throw unverified(`La atestación de ${entry.validator_id} no verifica contra la clave pública de su entrada`);
        }
    }
    return {
        format: VALIDATOR_MANIFEST_ANCHORED_FORMAT,
        chain_id: m.chain_id,
        quorum: FINALITY_QUORUM,
        validators: entries,
        manifest_fingerprint: m.manifest_fingerprint,
        attestations: entries.map((e) => ({
            validator_id: e.validator_id,
            signature: attBy.get(e.validator_id),
        })),
    };
}
/**
 * Paso 4 del orden de verificación (FUZZ-1 · REM-FZ-01): por cada
 * entrada del manifiesto YA verificado, el fichero de clave del
 * directorio se decodifica con todas las reglas KS (incluida la
 * ligadura pública↔privada del propio decode) y se contrasta contra
 * la entrada: el id decodificado, la pública DERIVADA y la huella
 * recomputada sobre {id de la entrada, pública derivada}. Los fallos
 * de contraste o de huella son KEYSTORE_KEY_ANCHOR_MISMATCH; los
 * fallos del propio decode conservan su código KS (sin frase, frase
 * errónea, formato). Devuelve las claves privadas en memoria.
 */
export function verifyValidatorKeyFilesAgainstManifest(dir, manifest, passphrase) {
    const keys = new Map();
    for (const entry of manifest.validators) {
        const keyFile = decodeValidatorKeyFile(readFileSync(join(dir, `${entry.validator_id}.json`), "utf8"), passphrase);
        if (keyFile.validator_id !== entry.validator_id || keyFile.publicKey !== entry.public_key) {
            throw new KeystoreError("KEYSTORE_KEY_ANCHOR_MISMATCH", `El fichero de claves de ${entry.validator_id} no coincide con su entrada del manifiesto anclado`);
        }
        if (validatorKeyFingerprint(entry.validator_id, keyFile.publicKey) !== entry.key_fingerprint) {
            throw new KeystoreError("KEYSTORE_KEY_ANCHOR_MISMATCH", `La huella de clave registrada para ${entry.validator_id} no recomputa desde su fichero de clave`);
        }
        keys.set(entry.validator_id, keyFile.privateKey);
    }
    return keys;
}
/**
 * La proyección operacional del manifiesto anclado: la forma V1 que
 * los consumidores de siempre reciben (certificados, época, red).
 * La época del conjunto se deriva de ESTA proyección, exactamente
 * como antes del ancla: anclar el directorio no rota ninguna época.
 */
export function operationalValidatorManifest(m) {
    return {
        format: "MT-VALIDATOR-MANIFEST-1",
        chain_id: m.chain_id,
        quorum: m.quorum,
        validators: m.validators.map((v) => ({ validator_id: v.validator_id, public_key: v.public_key })),
    };
}
export function transitionBytes(d) {
    return canonicalBytes({
        chain_id: d.chain_id,
        kind: d.kind,
        prev_state: d.prev_state,
        sequence: d.sequence,
        transition_hash: d.transition_hash,
    });
}
export class ConsensusError extends Error {
    code;
    constructor(code, message) {
        super(message);
        this.code = code;
        this.name = "ConsensusError";
    }
}
/**
 * Libro de votos + registro de equívocos. Es la pieza que hace cumplir el
 * bloqueo por secuencia: por cada (chain_id, kind, sequence) cada validador
 * tiene como máximo UNA huella votada. Cualquier segunda huella distinta es
 * un equívoco: se registra la evidencia y se rechaza.
 */
export class VoteLedger {
    voted = new Map();
    equivocations = [];
    keyOf(chainId, kind, sequence) {
        return `${chainId}|${kind}|${sequence}`;
    }
    /** Huella que un validador ya votó para esa secuencia, si votó alguna. */
    recordedHash(validatorId, d) {
        return this.voted.get(this.keyOf(d.chain_id, d.kind, d.sequence))?.get(validatorId);
    }
    recordEquivocation(r) {
        const canon = canonicalize(r);
        if (!this.equivocations.some((e) => canonicalize(e) === canon)) {
            this.equivocations.push(r);
        }
    }
    /** Restaura evidencia persistida (sin restaurar votos: solo el registro). */
    seedEvidence(records) {
        for (const r of records)
            this.recordEquivocation(r);
    }
    /**
     * Espejo en memoria de un voto YA emitido por la custodia duradera
     * (MT-VOTELEDGER-2): la autoridad anti-equivocación es el registro
     * duradero; este espejo mantiene observables el voto y la evidencia para
     * los recolectores. Un conflicto aquí también es equívoco registrado.
     */
    noteCustodyVote(validatorId, d) {
        const key = this.keyOf(d.chain_id, d.kind, d.sequence);
        let byValidator = this.voted.get(key);
        if (!byValidator) {
            byValidator = new Map();
            this.voted.set(key, byValidator);
        }
        const prev = byValidator.get(validatorId);
        if (prev === undefined) {
            byValidator.set(validatorId, d.transition_hash);
            return;
        }
        if (prev === d.transition_hash)
            return;
        this.recordEquivocation({
            validator_id: validatorId,
            chain_id: d.chain_id,
            kind: d.kind,
            sequence: d.sequence,
            first_transition_hash: prev,
            conflicting_transition_hash: d.transition_hash,
            evidence: "SECOND_SIGNATURE_ATTEMPT",
        });
        throw new ConsensusError("CONSENSUS_EQUIVOCATION", `${validatorId} ya votó otra transición para ${d.kind}#${d.sequence} (espejo en memoria)`);
    }
    /**
     * Puerta de custodia: se consulta ANTES de firmar. Devuelve "new" si es el
     * primer voto del validador para la secuencia y "duplicate" si ya votó la
     * MISMA transición. Si la huella difiere: equívoco — evidencia + rechazo.
     */
    assertSignable(validatorId, d) {
        const key = this.keyOf(d.chain_id, d.kind, d.sequence);
        let byValidator = this.voted.get(key);
        if (!byValidator) {
            byValidator = new Map();
            this.voted.set(key, byValidator);
        }
        const prev = byValidator.get(validatorId);
        if (prev === undefined) {
            byValidator.set(validatorId, d.transition_hash);
            return "new";
        }
        if (prev === d.transition_hash)
            return "duplicate";
        this.recordEquivocation({
            validator_id: validatorId,
            chain_id: d.chain_id,
            kind: d.kind,
            sequence: d.sequence,
            first_transition_hash: prev,
            conflicting_transition_hash: d.transition_hash,
            evidence: "SECOND_SIGNATURE_ATTEMPT",
        });
        throw new ConsensusError("CONSENSUS_EQUIVOCATION", `${validatorId} ya firmó otra transición para ${d.kind}#${d.sequence}: segunda firma rechazada y equívoco registrado`);
    }
    /**
     * Registra un voto presentado desde fuera (p. ej. una firma producida sin
     * pasar por la custodia). Misma regla: huella distinta a la ya votada por
     * ese validador para la secuencia = equívoco evidenciado y voto rechazado.
     */
    presentVote(validatorId, d) {
        const prev = this.recordedHash(validatorId, d);
        if (prev === d.transition_hash)
            return "duplicate";
        if (prev !== undefined) {
            this.recordEquivocation({
                validator_id: validatorId,
                chain_id: d.chain_id,
                kind: d.kind,
                sequence: d.sequence,
                first_transition_hash: prev,
                conflicting_transition_hash: d.transition_hash,
                evidence: "CONFLICTING_VOTE_PRESENTED",
            });
            throw new ConsensusError("CONSENSUS_EQUIVOCATION", `Voto conflictivo de ${validatorId} para ${d.kind}#${d.sequence}: rechazado y equívoco registrado`);
        }
        const key = this.keyOf(d.chain_id, d.kind, d.sequence);
        let byValidator = this.voted.get(key);
        if (!byValidator) {
            byValidator = new Map();
            this.voted.set(key, byValidator);
        }
        byValidator.set(validatorId, d.transition_hash);
        return "new";
    }
}
/**
 * Colector de votos para UNA transición: verifica cada firma contra el
 * manifiesto, deduplica por validador y decide la finalidad (>= quórum de
 * firmantes distintos). Sin atajos: una firma inválida o de un desconocido
 * aborta la recolección con error estable.
 */
export class FinalityCollector {
    manifest;
    ledger;
    transition;
    byValidator = new Map();
    constructor(manifest, ledger, transition) {
        this.manifest = manifest;
        this.ledger = ledger;
        this.transition = transition;
        // Esquema cerrado (R5.2): la transición sometida a finalidad es
        // exactamente el descriptor de 5 campos. Un campo extra —que
        // transitionBytes descartaría en silencio al reconstruir los bytes—
        // se rechaza aquí, antes de recoger un solo voto.
        const extra = firstUnknownField(transition, TRANSITION_DESCRIPTOR_FIELDS);
        if (extra !== null) {
            throw new ConsensusError("SCHEMA_FIELD_NOT_ALLOWED", schemaFieldNotAllowedMessage("el descriptor de transición", extra));
        }
    }
    addVote(vote) {
        // Esquema cerrado (R5.2): un voto es exactamente {validator_id, signature}.
        const extraVote = firstUnknownField(vote, VOTE_FIELDS);
        if (extraVote !== null) {
            throw new ConsensusError("SCHEMA_FIELD_NOT_ALLOWED", schemaFieldNotAllowedMessage("el voto", extraVote));
        }
        const entry = this.manifest.validators.find((v) => v.validator_id === vote.validator_id);
        if (!entry) {
            throw new ConsensusError("CONSENSUS_UNKNOWN_VALIDATOR", `Validador no presente en el manifiesto: ${vote.validator_id}`);
        }
        if (this.byValidator.has(vote.validator_id)) {
            return { counted: false, duplicate: true };
        }
        if (!verifyMlDsa87(entry.public_key, transitionBytes(this.transition), Buffer.from(vote.signature, "base64"))) {
            throw new ConsensusError("CONSENSUS_INVALID_SIGNATURE", `Firma inválida de ${vote.validator_id} sobre la transición`);
        }
        this.ledger.presentVote(vote.validator_id, this.transition);
        this.byValidator.set(vote.validator_id, vote);
        return { counted: true, duplicate: false };
    }
    get distinctCount() {
        return this.byValidator.size;
    }
    isFinal() {
        return this.distinctCount >= this.manifest.quorum;
    }
    certificate() {
        if (!this.isFinal()) {
            throw new ConsensusError("CONSENSUS_QUORUM_UNAVAILABLE", `La transición ${this.transition.kind}#${this.transition.sequence} no alcanza el quórum: ${this.distinctCount}/${this.manifest.quorum} firmas distintas`);
        }
        return {
            transition: { ...this.transition },
            votes: [...this.byValidator.values()],
        };
    }
}
/** Verificación independiente de un certificado contra un manifiesto. */
export function verifyCertificate(manifest, cert) {
    const errors = [];
    // Esquema cerrado (R5.2): certificado, transición y cada voto deben ser
    // EXACTAMENTE sus campos de esquema. Sin este control, transitionBytes()
    // reconstruiría los bytes firmados solo con los campos conocidos y un
    // campo extra presentado junto al objeto pasaría inadvertido: la
    // estructura verificada no sería la estructura presentada. El rechazo
    // es previo a cualquier verificación de firma (fail-closed).
    const extraCert = firstUnknownField(cert, FINALITY_CERTIFICATE_FIELDS);
    if (extraCert !== null) {
        errors.push(schemaFieldNotAllowedMessage("el certificado de finalidad", extraCert));
    }
    const extraTrans = firstUnknownField(cert?.transition, TRANSITION_DESCRIPTOR_FIELDS);
    if (extraTrans !== null) {
        errors.push(schemaFieldNotAllowedMessage("el descriptor de transición del certificado", extraTrans));
    }
    if (Array.isArray(cert?.votes)) {
        for (const vote of cert.votes) {
            const extraVote = firstUnknownField(vote, VOTE_FIELDS);
            if (extraVote !== null) {
                errors.push(schemaFieldNotAllowedMessage("un voto del certificado", extraVote));
            }
        }
    }
    if (errors.length > 0) {
        return { valid: false, distinct_signers: 0, errors };
    }
    const t = cert.transition;
    if (t.chain_id !== manifest.chain_id) {
        errors.push(`El certificado es de otra cadena (${t.chain_id} != ${manifest.chain_id})`);
    }
    const distinct = new Set();
    for (const vote of cert.votes) {
        const entry = manifest.validators.find((v) => v.validator_id === vote.validator_id);
        if (!entry) {
            errors.push(`Voto de un validador fuera del manifiesto: ${vote.validator_id}`);
            continue;
        }
        if (!verifyMlDsa87(entry.public_key, transitionBytes(t), Buffer.from(vote.signature, "base64"))) {
            errors.push(`Firma inválida de ${vote.validator_id}`);
            continue;
        }
        distinct.add(vote.validator_id);
    }
    if (distinct.size < manifest.quorum) {
        errors.push(`Quórum no alcanzado: ${distinct.size}/${manifest.quorum} firmantes distintos`);
    }
    return { valid: errors.length === 0, distinct_signers: distinct.size, errors };
}
/**
 * Conjunto de validadores de testnet con custodia separada por validador.
 * Las claves privadas se cargan desde un fichero por validador y NUNCA se
 * exponen: la única operación posible es firmar a través de `signAs`, que
 * pasa siempre por el libro de votos (bloqueo por secuencia).
 */
export class ValidatorSet {
    manifest;
    ledger = new VoteLedger();
    /** Época del conjunto activo (identidad derivada del manifiesto). */
    epoch;
    privateKeys = new Map();
    custody = new Map();
    constructor(manifest, privateKeys, custody, epoch) {
        this.manifest = manifest;
        this.privateKeys = privateKeys;
        this.custody = custody;
        this.epoch = epoch;
    }
    /**
     * Abre la custodia duradera (MT-VOTELEDGER-2) de cada validador sobre el
     * manifiesto cargado/creado y devuelve el conjunto listo. La apertura
     * VERIFICA cada registro (cadena de hashes, checksums, ancla): cualquier
     * corrupción, rollback o desajuste de (cadena, época) aborta la carga —
     * sin custodia verificada no hay firma posible (fail-closed). Los
     * intentos de equívoco persistidos se espejan en el VoteLedger en
     * memoria como evidencia.
     */
    static finishLoad(dir, chainId, manifest, keys, opts) {
        const epoch = opts?.epoch ?? validatorSetEpoch(manifest);
        const custody = new Map();
        const set = new ValidatorSet(manifest, keys, custody, epoch);
        for (const entry of manifest.validators) {
            let durable;
            try {
                durable = DurableVoteLedger.open(voteLedgerPath(dir, entry.validator_id), { chainId, validatorId: entry.validator_id, epoch }, opts?.crashHooks, { witnessDir: opts?.witnessDir });
            }
            catch (e) {
                // La carga aborta con el código estable de la custodia: sin
                // registro verificado no existe conjunto que pueda firmar.
                if (e instanceof VoteLedgerCustodyError)
                    throw new ConsensusError(e.code, e.message);
                throw e;
            }
            custody.set(entry.validator_id, durable);
            for (const att of durable.equivocationAttempts()) {
                set.ledger.recordEquivocation({ ...att });
            }
        }
        return set;
    }
    /**
     * Carga el conjunto desde `dir` o lo crea: genera 4 pares ML-DSA-87
     * independientes, un fichero por validador (con su clave privada de
     * testnet) y el manifiesto ANCLADO MT-VALIDATOR-MANIFEST-2 (huella
     * por entrada, huella del manifiesto y atestación de cada
     * validador, firmadas en la creación con las claves en memoria).
     * La carga verifica el ancla entera antes de abrir custodia alguna
     * (verifyAnchoredValidatorManifest + paso 4 contra los ficheros);
     * el manifiesto legado V1 ya no entra por esta puerta: solo por la
     * migración gobernada registrada.
     */
    static loadOrCreate(dir, chainId, opts) {
        const manifestPath = join(dir, "manifest.json");
        if (existsSync(manifestPath)) {
            let parsed;
            try {
                parsed = JSON.parse(readFileSync(manifestPath, "utf8"));
            }
            catch {
                throw new KeystoreError("KEYSTORE_MANIFEST_UNVERIFIED", `El manifiesto de validadores en ${dir} no es JSON válido: no verifica`);
            }
            const anchored = verifyAnchoredValidatorManifest(parsed, chainId);
            const keys = verifyValidatorKeyFilesAgainstManifest(dir, anchored, opts?.keyPassphrase);
            return ValidatorSet.finishLoad(dir, chainId, operationalValidatorManifest(anchored), keys, opts);
        }
        mkdirSync(dir, { recursive: true });
        const material = [];
        // Escritura SOLO por el códec del modo elegido: "plain" (defecto)
        // produce el MT-VALIDATOR-KEY-1 histórico byte a byte; "encrypted"
        // sella cada clave como MT-VALIDATOR-KEY-2.
        const codec = keyCustodyFor(opts?.keyProtection ?? "plain");
        for (const id of VALIDATOR_IDS) {
            const pair = generateMlDsa87();
            writeFileSync(join(dir, `${id}.json`), codec.encode({ validator_id: id, publicKey: pair.publicKey, privateKey: pair.privateKey }, opts?.keyPassphrase), "utf8");
            material.push({ validator_id: id, public_key: pair.publicKey, private_key: pair.privateKey });
        }
        // El conjunto NACE anclado: el manifiesto que se escribe es el
        // MT-VALIDATOR-MANIFEST-2, atestiguado aquí con las claves en
        // memoria (la firma solo ocurre en creación y en la migración
        // gobernada; la carga jamás firma).
        const anchored = buildAnchoredValidatorManifest({ chainId, keys: material });
        writeFileSync(manifestPath, JSON.stringify(anchored, null, 2) + "\n", "utf8");
        const keys = new Map(material.map((k) => [k.validator_id, k.private_key]));
        return ValidatorSet.finishLoad(dir, chainId, operationalValidatorManifest(anchored), keys, opts);
    }
    /**
     * Custodia: firma la transición SOLO con la clave de `validatorId`, y
     * SOLO a través del registro duradero (MT-VOTELEDGER-2): primero se
     * persiste el compromiso de voto con fsync, después se firma, y la
     * firma se persiste antes de entregarse. Re-votar la transición
     * idéntica devuelve la firma original registrada (idempotente). Un
     * conflicto se rechaza con CONSENSUS_EQUIVOCATION y queda registrado
     * como intento de equivocación en el registro DURADERO.
     */
    signAs(validatorId, d) {
        return this.signLedgerBound(validatorId, d, transitionBytes(d));
    }
    /**
     * Pipeline de custodia con mensaje explícito (MOTOR 2 — emisión de
     * finalidad v2): firma `message` —los bytes exactos que define el
     * llamante— a través del registro duradero, con la misma ley de
     * hierro que signAs (compromiso con fsync ANTES de firmar; firma
     * persistida ANTES de entregarse). signAs es este pipeline con el
     * mensaje v1 (transitionBytes); el colector v2 lo usa con el mensaje
     * MT-FINALITY-V1 (finalityMessageV2Bytes).
     *
     * La devolución idempotente NO re-verifica la firma registrada
     * contra el mensaje pedido: la custodia liga por (kind, sequence,
     * transition_hash) y la firma persistida liga los bytes del
     * descriptor con el que se firmó — comportamiento fijado por
     * A7-IMP-03 (battery19), que además fija que el rechazo al
     * emparejar una firma con un descriptor/mensaje que no es el suyo
     * vive en los COLECTORES (el v1: FinalityCollector, con
     * CONSENSUS_INVALID_SIGNATURE; el v2: collectCertificateV2, con el
     * mismo código). Aquí no se añade ningún juicio: una primera versión
     * de este pipeline verificaba al reanudar y battery19 la cazó
     * rompiendo A7-IMP-03; la corrección movió el juicio a su capa.
     */
    signLedgerBound(validatorId, d, message) {
        const privateKey = this.privateKeys.get(validatorId);
        if (!privateKey) {
            throw new ConsensusError("CONSENSUS_UNKNOWN_VALIDATOR", `Sin custodia para el validador: ${validatorId}`);
        }
        const durable = this.custody.get(validatorId);
        if (!durable) {
            throw new ConsensusError("CONSENSUS_UNKNOWN_VALIDATOR", `Sin custodia duradera para el validador: ${validatorId}`);
        }
        let prep;
        try {
            prep = durable.prepareVote(d);
        }
        catch (e) {
            if (e instanceof VoteLedgerCustodyError) {
                if (e.code === "VOTELEDGER_EQUIVOCATION" && e.equivocation) {
                    this.ledger.recordEquivocation(e.equivocation);
                    throw new ConsensusError("CONSENSUS_EQUIVOCATION", e.message);
                }
                throw new ConsensusError(e.code, e.message);
            }
            throw e;
        }
        if (prep.status === "signed") {
            this.ledger.noteCustodyVote(validatorId, d);
            return { validator_id: validatorId, signature: prep.signature };
        }
        const signature = signMlDsa87(privateKey, message).toString("base64");
        try {
            durable.persistSignature(d, signature);
        }
        catch (e) {
            // La firma producida se DESCARTA: sin persistencia previa no hay
            // entrega. Reintentar la misma petición es seguro (idempotente).
            if (e instanceof VoteLedgerCustodyError)
                throw new ConsensusError(e.code, e.message);
            throw e;
        }
        this.ledger.noteCustodyVote(validatorId, d);
        return { validator_id: validatorId, signature };
    }
    /**
     * Prueba de admisión (MT-VALIDATOR-MANIFEST-CHAIN-1, cierre F-A6-01):
     * firma un mensaje de prueba de posesión con la clave del validador.
     * NO es un voto: no es una transición de finalidad, no pasa por el
     * registro duradero de votos y no puede crear equívocos — su dominio
     * firmado (MT-VALIDATOR-POP-1) es disjunto del de cualquier transición
     * (GENESIS/MINT_BRICK/OPLOG_*). La custodia duradera protege VOTOS;
     * esta es la credencial con la que una clave se presenta a un
     * manifiesto, y su único productor legítimo es la construcción del
     * manifiesto canónico del propio conjunto.
     */
    signAdmissionProof(validatorId, message) {
        const privateKey = this.privateKeys.get(validatorId);
        if (!privateKey) {
            throw new ConsensusError("CONSENSUS_UNKNOWN_VALIDATOR", `Sin custodia para el validador: ${validatorId}`);
        }
        return signMlDsa87(privateKey, message).toString("base64");
    }
    /**
     * Snapshot AUTENTICADO del registro duradero de un validador: el núcleo
     * del snapshot firmado con la clave ML-DSA-87 de ese validador sobre sus
     * bytes canónicos (el campo format hace la separación de dominio).
     * Base de la recuperación verificada (ver DurableVoteLedger.restoreFromSnapshot).
     */
    signVoteSnapshot(validatorId) {
        const privateKey = this.privateKeys.get(validatorId);
        const durable = this.custody.get(validatorId);
        if (!privateKey || !durable) {
            throw new ConsensusError("CONSENSUS_UNKNOWN_VALIDATOR", `Sin custodia para el validador: ${validatorId}`);
        }
        const core = durable.snapshotCore();
        return {
            core,
            signature: signMlDsa87(privateKey, canonicalBytes(core)).toString("base64"),
        };
    }
    /** Huella del estado anti-equivocación duradero de un validador. */
    voteStateDigest(validatorId) {
        const durable = this.custody.get(validatorId);
        if (!durable) {
            throw new ConsensusError("CONSENSUS_UNKNOWN_VALIDATOR", `Sin custodia duradera para el validador: ${validatorId}`);
        }
        return durable.stateDigest();
    }
    /**
     * Prueba de recuperación (VoteLedgerRecoveryProof) emitida al abrir la
     * custodia de un validador: la comparación de continuidad contra su
     * testigo externo que habilitó (o habría deshabilitado) la firma.
     */
    voteRecoveryProof(validatorId) {
        const durable = this.custody.get(validatorId);
        if (!durable) {
            throw new ConsensusError("CONSENSUS_UNKNOWN_VALIDATOR", `Sin custodia duradera para el validador: ${validatorId}`);
        }
        return durable.recoveryProof();
    }
    /**
     * Compactación segura del registro duradero de un validador
     * (MT-WAL-COMPACT-1): base snapshot con compromiso en el testigo
     * externo registrado antes de podar; el estado anti-equivocación —
     * votos, firmas y evidencia de intentos— se conserva íntegro.
     */
    compactVoteLedger(validatorId, hooks) {
        const durable = this.custody.get(validatorId);
        if (!durable) {
            throw new ConsensusError("CONSENSUS_UNKNOWN_VALIDATOR", `Sin custodia duradera para el validador: ${validatorId}`);
        }
        try {
            return durable.compact(hooks);
        }
        catch (e) {
            if (e instanceof VoteLedgerCustodyError)
                throw new ConsensusError(e.code, e.message);
            throw e;
        }
    }
    /** Líneas del registro duradero posteriores a una entrada (para restaurar). */
    exportVoteTail(validatorId, afterSeq) {
        const durable = this.custody.get(validatorId);
        if (!durable) {
            throw new ConsensusError("CONSENSUS_UNKNOWN_VALIDATOR", `Sin custodia duradera para el validador: ${validatorId}`);
        }
        return durable.exportTailLines(afterSeq);
    }
    collector(d) {
        return new FinalityCollector(this.manifest, this.ledger, d);
    }
}
/**
 * Recoge el certificado de finalidad de una transición firmando con los
 * validadores indicados (por defecto, los 4). Si no se alcanza el quórum de
 * firmantes distintos, lanza CONSENSUS_QUORUM_UNAVAILABLE: la transición NO
 * es final y el llamante no debe persistirla.
 */
export function collectCertificate(set, d, signerIds) {
    const collector = set.collector(d);
    const ids = signerIds ?? set.manifest.validators.map((v) => v.validator_id);
    for (const id of ids) {
        collector.addVote(set.signAs(id, d));
    }
    return collector.certificate();
}
