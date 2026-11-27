/**
 * Fase 3 · Contrato de datos cerrado — BrickIdentityV2 (fallo V1.2, E1.1/E1.2).
 *
 * El contenido que aporta el comprador es EXACTAMENTE: nombre + país + modo.
 * No existe historia, mensaje, foto, PDF ni ningún otro campo. Un campo
 * desconocido NO se ignora en silencio: la operación se rechaza con el error
 * estable SCHEMA_FIELD_NOT_ALLOWED nombrando el campo (regla V1.2 §1.6).
 */
import { isValidCountry } from "./countries.js";
export class SchemaError extends Error {
    code;
    field;
    constructor(code, message, field) {
        super(message);
        this.code = code;
        this.field = field;
        this.name = "SchemaError";
    }
}
const ALLOWED_FIELDS = new Set(["name", "country", "privacy"]);
/** Controles invisibles de dirección y marcas de formato prohibidas (E1.1). */
const INVISIBLE_FORMAT_RE = /[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]/;
/** Control: C0/C1 (<0x20, 0x7F–0x9F) y sustitutos solitarios. La iteración por
 *  puntos de código deja pasar los pares válidos (emoji, etc.) y expone el
 *  sustituto desemparejado con su propio valor. */
function hasForbiddenControl(s) {
    for (const ch of s) {
        const cp = ch.codePointAt(0);
        if (cp < 0x20 || (cp >= 0x7f && cp <= 0x9f))
            return true;
        if (cp >= 0xd800 && cp <= 0xdfff)
            return true;
    }
    return false;
}
/* ------------------------------------------------------------------ */
/* Esquemas cerrados reutilizables (evidencia PQ, ronda 5 — R5.2).     */
/*                                                                     */
/* La doctrina de BrickIdentityV2 (regla V1.2 §1.6) aplicada a todos   */
/* los objetos críticos firmados/verificados de la cadena: un campo    */
/* fuera del esquema NO se descarta en silencio; se rechaza con        */
/* SCHEMA_FIELD_NOT_ALLOWED nombrando el campo. La estructura          */
/* validada debe ser exactamente la firmada, la verificada, la         */
/* interpretada y la registrada: ningún parser puede recortar campos   */
/* y verificar una versión reducida del objeto presentado.             */
/* ------------------------------------------------------------------ */
/** Campos exactos de cada objeto crítico (fuente única de la doctrina). */
export const TRANSITION_DESCRIPTOR_FIELDS = [
    "chain_id",
    "kind",
    "sequence",
    "prev_state",
    "transition_hash",
];
export const VOTE_FIELDS = ["validator_id", "signature"];
export const FINALITY_CERTIFICATE_FIELDS = ["transition", "votes"];
export const STATE_CHECKPOINT_FIELDS = [
    "format",
    "chain_id",
    "epoch",
    "version",
    "state_root",
    "block_root",
    "oplog_merkle_root",
    "latest_brick",
    "latest_op_seq",
    "ecola_root",
    "ecola_count",
    "ecola_last_seq",
    "timestamp_ms",
    "checkpoint_public_key",
    "signature",
];
/** Forma legada de checkpoint en paquetes antiguos de mt-verify. */
export const LEGACY_CHECKPOINT_FIELDS = ["root", "block_count", "signature"];
export const PURPOSE_SIGNATURE_FIELDS = ["purpose", "epoch", "signature"];
export const KEY_TRANSITION_FIELDS = [
    "type",
    "purpose",
    "from_epoch",
    "to_epoch",
    "new_public_key",
    "authorizer",
    "seq",
    "signature",
];
export const SIGNED_INTENT_ENVELOPE_FIELDS = ["intent", "signature"];
/* Objetos del puente (paso A5 — DIF/SCH extendido a la frontera): los
 * artefactos que cruzan entre casa, la extranjera simulada y mt-verify
 * quedan bajo la misma doctrina de esquema cerrado. `reference` del
 * registro es opcional (ausente en TRANSFER históricos), pero ningún
 * campo fuera de la lista se acepta. */
export const OPLOG_ENTRY_FIELDS = [
    "op_seq",
    "kind",
    "brick_number",
    "from_commitment",
    "to_commitment",
    "price_cents",
    "reference",
    "prev_oplog_hash",
    "entry_hash",
    "finality",
];
export const BRIDGE_LOCK_PROOF_FIELDS = ["format", "label", "entry", "checkpoint"];
export const FOREIGN_BURN_PROOF_FIELDS = [
    "format",
    "label",
    "foreign_chain_id",
    "brick_number",
    "burner_account",
    "burn_seq",
    "burn_record_hash",
    "proof_hash",
];
export const FOREIGN_RECORD_FIELDS = ["seq", "kind", "data", "prev_hash", "hash"];
export const BRIDGE_PROOF_PACKAGE_FIELDS = [
    "format",
    "chain_id",
    "label",
    "validator_manifest",
    "lock_proof",
    "burn_proof",
    "foreign_records",
    // Sección opcional de cadena de manifiestos (cierre F-A6-01): si el
    // paquete la trae, mt-verify la verifica y la cruza con el manifiesto
    // plano; si no la trae, el componente queda SKIPPED declarado (legado).
    "manifest_chain",
];
/* Sobre de la ruta de ladrillo MT-BRICK-PROOF-1 (F-20-02, remediación
 * C-AUD-20): la ruta cerraba el manifiesto y sus entradas, pero no el
 * paquete mismo, ni el sujeto, ni los parámetros públicos — las rutas
 * de puente y de manifiesto sí cierran sus sobres. Listas derivadas de
 * las interfaces del productor (src/proof.ts: BrickProofPackage y
 * ProofSubject), que son la forma exacta que exportBrickProof emite. */
export const BRICK_PROOF_PACKAGE_FIELDS = [
    "format",
    "chain_id",
    "suite_id",
    "network",
    "constitution_fingerprint",
    "height",
    "subject",
    "genesis",
    "blocks",
    "public_parameters",
    "checkpoint",
];
export const BRICK_PROOF_SUBJECT_FIELDS = [
    "brick_number",
    "privacy",
    "inscription",
    "identity_commitment",
    "ownership_commitment",
    "position_factor_parts",
    "position_factor",
];
export const BRICK_PROOF_INSCRIPTION_FIELDS = ["name", "country"];
export const BRICK_PROOF_POSITION_FACTOR_PARTS_FIELDS = ["numerator", "denominator"];
export const BRICK_PROOF_PUBLIC_PARAMETERS_FIELDS = [
    "validator_manifest",
    "checkpoint_public_key",
    "manifest_chain",
];
/** El manifiesto de validadores también es evidencia que cruza superficies
 *  (va dentro de los paquetes): queda bajo la misma doctrina (hallazgo del
 *  fuzzing de A5, errata 01: ninguna superficie lo cerraba). */
export const VALIDATOR_MANIFEST_FIELDS = ["format", "chain_id", "quorum", "validators"];
export const VALIDATOR_MANIFEST_ENTRY_FIELDS = ["validator_id", "public_key"];
/* Cadena de manifiestos anclada (MT-VALIDATOR-MANIFEST-CHAIN-1, cierre
 * estructural de F-A6-01 — adjudicación de la casa de 2026-11-06 sobre los
 * fallos GPT Extra High y DeepSeek DeepThink). Las listas concretas las
 * diseña el implementador desde los REQUISITOS de ambos fallos (las listas
 * de GPT llegaron truncadas en la extracción); quedan sometidas a la
 * aprobación de la casa en el informe de cierre. Fuente única de la
 * doctrina: productores (src/manifest-chain.ts) y mt-verify comparten
 * estas listas, como ya comparten las del manifiesto operativo. */
export const FINALITY_POLICY_FIELDS = [
    "format",
    "chain_id",
    "network_id",
    "validator_count",
    "quorum",
    "signature_algorithm",
    "finality_message_domain",
    "certificate_format",
];
export const TRANSITION_POLICY_FIELDS = [
    "format",
    "chain_id",
    "network_id",
    "cold_signature_algorithm",
    "cold_threshold",
    "cold_custodian_count",
    "cold_authority_seated",
    "max_simultaneous_replacements",
    "requires_proof_of_possession",
    "transition_message_domain",
];
/** Manifiesto canónico encadenado (MT-VALIDATOR-MANIFEST-1, schema_version "1"). */
export const CANONICAL_MANIFEST_FIELDS = [
    "format",
    "schema_version",
    "chain_id",
    "network_id",
    "epoch",
    "effective_height",
    "prev_manifest_hash",
    "finality_policy_hash",
    "transition_policy_hash",
    "validators",
];
export const CANONICAL_MANIFEST_ENTRY_FIELDS = [
    "validator_id",
    "public_key",
    "purpose",
    "proof_of_possession",
];
/** Objeto externo de bootstrap de testnet (MT-VALIDATOR-MANIFEST-BOOTSTRAP-1). */
export const MANIFEST_BOOTSTRAP_FIELDS = [
    "format",
    "chain_id",
    "network_id",
    "genesis_hash",
    "bootstrap_epoch",
    "bootstrap_height",
    "initial_manifest_hash",
    "finality_policy_hash",
    "transition_policy_hash",
    "cold_authority",
    "finality_activation_height",
];
export const COLD_AUTHORITY_FIELDS = ["custodians", "threshold"];
export const COLD_CUSTODIAN_FIELDS = ["custodian_id", "public_key"];
/** Transición de conjunto (MT-VALIDATOR-SET-TRANSITION-1). */
export const SET_TRANSITION_FIELDS = [
    "format",
    "schema_version",
    "chain_id",
    "network_id",
    "old_epoch",
    "new_epoch",
    "old_manifest_hash",
    "new_manifest_hash",
    "transition_height",
    "effective_height",
    "transition_policy_hash",
    "nonce",
    "retired_validator_ids",
    "added_validator_ids",
    "survivor_signatures",
    "cold_signatures",
];
/** El tuplo que firman AMBAS autorizaciones (supervivientes y autoridad fría). */
export const TRANSITION_TUPLE_FIELDS = [
    "domain",
    "chain_id",
    "old_epoch",
    "new_epoch",
    "old_manifest_hash",
    "new_manifest_hash",
    "transition_height",
    "effective_height",
    "transition_policy_hash",
    "nonce",
];
export const SURVIVOR_SIGNATURE_FIELDS = ["validator_id", "signature"];
export const COLD_SIGNATURE_FIELDS = ["custodian_id", "signature"];
/** Mensaje de prueba de posesión de una clave nueva (MT-VALIDATOR-POP-1). */
export const POP_MESSAGE_FIELDS = [
    "domain",
    "chain_id",
    "epoch",
    "manifest_hash",
    "validator_id",
    "public_key",
];
/** Certificado de finalidad v2 (MT-FINALITY-CERTIFICATE-2, activación versionada). */
export const FINALITY_CERTIFICATE_V2_FIELDS = [
    "format",
    "transition",
    "epoch",
    "manifest_hash",
    "votes",
];
/** Mensaje firmado de finalidad v2 (dominio MT-FINALITY-V1). */
export const FINALITY_MESSAGE_V2_FIELDS = [
    "domain",
    "chain_id",
    "kind",
    "sequence",
    "prev_state",
    "transition_hash",
    "epoch",
    "view",
    "manifest_hash",
];
/** Sección de cadena de manifiestos dentro de los parámetros públicos de un paquete. */
export const MANIFEST_CHAIN_SECTION_FIELDS = ["bootstrap", "manifests", "transitions"];
/** Bloque de la evidencia MT-MANIFEST-CHAIN-PROOF-1. */
export const MANIFEST_CHAIN_BLOCK_FIELDS = [
    "height",
    "kind",
    "prev_hash",
    "block_hash",
    "transition_hash",
    "payload_hash",
    "finality",
];
export const MANIFEST_CHAIN_PROOF_FIELDS = [
    "format",
    "chain_id",
    "network_id",
    "bootstrap",
    "manifests",
    "transitions",
    "blocks",
];
/**
 * Primer campo de `obj` que no pertenece al esquema cerrado `allowed`,
 * o null si no hay ninguno (o si `obj` no es un objeto plano: eso lo
 * juzga la validación de forma de cada ruta, no esta función).
 */
export function firstUnknownField(obj, allowed) {
    if (typeof obj !== "object" || obj === null || Array.isArray(obj))
        return null;
    const set = new Set(allowed);
    for (const key of Object.keys(obj)) {
        if (!set.has(key))
            return key;
    }
    return null;
}
/** Mensaje estable del rechazo por campo desconocido, nombrando el campo. */
export function schemaFieldNotAllowedMessage(label, field) {
    return `SCHEMA_FIELD_NOT_ALLOWED: campo no permitido en ${label}: "${field}". El objeto es un esquema cerrado: ningún campo fuera de él se acepta ni se descarta en silencio.`;
}
/** Rechazo lanzado (variante para rutas que lanzan SchemaError). */
export function assertNoUnknownFields(obj, allowed, label) {
    const field = firstUnknownField(obj, allowed);
    if (field !== null) {
        throw new SchemaError("SCHEMA_FIELD_NOT_ALLOWED", schemaFieldNotAllowedMessage(label, field), field);
    }
}
const graphemeSegmenter = new Intl.Segmenter("und", { granularity: "grapheme" });
export function countGraphemes(s) {
    let n = 0;
    for (const _ of graphemeSegmenter.segment(s))
        n++;
    return n;
}
export function validateBrickIdentity(input) {
    if (typeof input !== "object" || input === null || Array.isArray(input)) {
        throw new SchemaError("SCHEMA_INVALID_TYPE", "La identidad del ladrillo debe ser un objeto JSON");
    }
    const obj = input;
    // 1) Campos desconocidos → rechazo nombrando el campo. Nunca se descartan en silencio.
    for (const key of Object.keys(obj)) {
        if (!ALLOWED_FIELDS.has(key)) {
            throw new SchemaError("SCHEMA_FIELD_NOT_ALLOWED", `Campo no permitido en BrickIdentityV2: "${key}". El contenido del ladrillo es solo nombre, país y modo de privacidad.`, key);
        }
    }
    // 2) Campos obligatorios.
    for (const key of ["name", "country", "privacy"]) {
        if (!(key in obj)) {
            throw new SchemaError("SCHEMA_FIELD_REQUIRED", `Falta el campo obligatorio: "${key}"`, key);
        }
    }
    // 3) Nombre: NFC, 1–64 grafemas, ≤256 bytes UTF-8, sin controles ni marcas invisibles.
    const rawName = obj.name;
    if (typeof rawName !== "string") {
        throw new SchemaError("SCHEMA_NAME_INVALID", "El nombre debe ser un string", "name");
    }
    const name = rawName.normalize("NFC");
    if (hasForbiddenControl(name)) {
        throw new SchemaError("SCHEMA_NAME_INVALID", "El nombre contiene caracteres de control o saltos de línea", "name");
    }
    if (INVISIBLE_FORMAT_RE.test(name)) {
        throw new SchemaError("SCHEMA_NAME_INVALID", "El nombre contiene controles invisibles de dirección o formato", "name");
    }
    const graphemes = countGraphemes(name);
    if (graphemes < 1 || graphemes > 64) {
        throw new SchemaError("SCHEMA_NAME_INVALID", `El nombre debe tener entre 1 y 64 grafemas; tiene ${graphemes}`, "name");
    }
    const byteLen = Buffer.byteLength(name, "utf8");
    if (byteLen > 256) {
        throw new SchemaError("SCHEMA_NAME_INVALID", `El nombre supera 256 bytes UTF-8 (${byteLen})`, "name");
    }
    // 4) País: ISO 3166-1 alpha-2 exacto contra el catálogo fijado.
    const country = obj.country;
    if (!isValidCountry(country)) {
        throw new SchemaError("SCHEMA_COUNTRY_INVALID", `País no válido (ISO 3166-1 alpha-2 del catálogo fijado): ${JSON.stringify(country)}`, "country");
    }
    // 5) Privacidad: exactamente PUBLIC o PRIVATE.
    const privacy = obj.privacy;
    if (privacy !== "PUBLIC" && privacy !== "PRIVATE") {
        throw new SchemaError("SCHEMA_PRIVACY_INVALID", `El modo debe ser exactamente "PUBLIC" o "PRIVATE"; recibido: ${JSON.stringify(privacy)}`, "privacy");
    }
    return { name, country, privacy };
}
