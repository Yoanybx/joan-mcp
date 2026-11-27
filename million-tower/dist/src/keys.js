/**
 * MT-ULTRA-1 · Claves y firmas (wrappers sobre node:crypto, Node >= 24).
 *  - Firmas de bloque/validador: ML-DSA-87 (FIPS 204) — SOPORTADO nativamente.
 *  - Checkpoints: SLH-DSA-SHAKE-256s (FIPS 205) — SOPORTADO nativamente en
 *    Node 24.22.1 (verificado el 2026-11-02: generateKeyPairSync('slh-dsa-shake-256s')
 *    genera, firma y verifica). Sin hueco que declarar en este runtime.
 *  - Encapsulado para identidad privada: ML-KEM-1024 (FIPS 203) — SOPORTADO.
 *
 * Canonicalidad estricta (evidencia PQ, sonda 03): el parser de OpenSSL
 * tolera mutaciones del SOBRE — una clave SPKI con bytes extra tras el DER
 * se importa y verifica contra la clave recuperada. Esta capa impone, ANTES
 * de verificar: base64 canónico exacto, DER SPKI sin bytes sobrantes con el
 * OID esperado y la longitud exacta de la clave cruda, re-exportación DER
 * byte-idéntica a la entrada, y longitud exacta de firmas y ciphertext KEM.
 */
import { createPrivateKey, createPublicKey, decapsulate, encapsulate, generateKeyPairSync, sign, verify, } from "node:crypto";
function exportPair(kp) {
    return {
        publicKey: kp.publicKey.export({ type: "spki", format: "der" }).toString("base64"),
        privateKey: kp.privateKey.export({ type: "pkcs8", format: "der" }).toString("base64"),
    };
}
/* ---------------- Canonicalidad estricta ---------------- */
export const ML_DSA_87_SIGNATURE_BYTES = 4627;
export const ML_DSA_87_PUBLIC_KEY_BYTES = 2592;
export const SLH_DSA_SHAKE_256S_SIGNATURE_BYTES = 29792;
export const SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES = 64;
export const ML_KEM_1024_PUBLIC_KEY_BYTES = 1568;
export const ML_KEM_1024_CIPHERTEXT_BYTES = 1568;
/** Contenido (sin tag ni longitud) del OID de cada algoritmo. */
const OID_CONTENT = {
    ML_DSA_87: Buffer.from("608648016503040313", "hex"), // 2.16.840.1.101.3.4.3.19
    SLH_DSA_SHAKE_256S: Buffer.from("60864801650304031e", "hex"), // 2.16.840.1.101.3.4.3.30
    ML_KEM_1024: Buffer.from("608648016503040403", "hex"), // 2.16.840.1.101.3.4.4.3
};
function decodeStrictBase64(b64) {
    const bytes = Buffer.from(b64, "base64");
    if (bytes.toString("base64") !== b64) {
        throw new Error("Representación base64 no canónica");
    }
    return bytes;
}
function readDerLength(buf, offset) {
    if (offset >= buf.length)
        return null;
    const first = buf[offset];
    if (first < 0x80)
        return { length: first, next: offset + 1 };
    const n = first & 0x7f;
    if (n === 0 || n > 2 || offset + 1 + n > buf.length)
        return null;
    let length = 0;
    for (let k = 0; k < n; k++)
        length = length * 256 + buf[offset + 1 + k];
    if (n === 1 && length < 128)
        return null; // forma larga no canónica
    if (n === 2 && length < 256)
        return null;
    return { length, next: offset + 1 + n };
}
function readDerTlv(buf, offset, tag) {
    if (offset >= buf.length || buf[offset] !== tag)
        return null;
    const len = readDerLength(buf, offset + 1);
    if (!len)
        return null;
    const contentEnd = len.next + len.length;
    if (contentEnd > buf.length)
        return null;
    return { contentStart: len.next, contentEnd, next: contentEnd };
}
/** Extrae la clave cruda de un SPKI DER estricto, o null si no es canónico. */
function parseSpkiRawKey(derBytes, expectedOidContent) {
    const outer = readDerTlv(derBytes, 0, 0x30);
    if (!outer || outer.next !== derBytes.length)
        return null; // sin bytes sobrantes
    const algSeq = readDerTlv(derBytes, outer.contentStart, 0x30);
    if (!algSeq)
        return null;
    const oid = readDerTlv(derBytes, algSeq.contentStart, 0x06);
    if (!oid || oid.next !== algSeq.contentEnd)
        return null;
    if (!derBytes.subarray(oid.contentStart, oid.contentEnd).equals(expectedOidContent))
        return null;
    const bits = readDerTlv(derBytes, algSeq.next, 0x03);
    if (!bits || bits.next !== outer.contentEnd)
        return null;
    if (derBytes[bits.contentStart] !== 0)
        return null; // BIT STRING sin bits sin usar
    return derBytes.subarray(bits.contentStart + 1, bits.contentEnd);
}
function importPublicKeyStrict(b64, oidContent, rawKeyBytes, algorithm) {
    const derBytes = decodeStrictBase64(b64);
    const raw = parseSpkiRawKey(derBytes, oidContent);
    if (!raw || raw.length !== rawKeyBytes) {
        throw new Error(`Clave pública ${algorithm} no canónica o de longitud inesperada`);
    }
    const key = createPublicKey({ key: derBytes, format: "der", type: "spki" });
    if (!key.export({ type: "spki", format: "der" }).equals(derBytes)) {
        throw new Error(`Clave pública ${algorithm} con DER no canónico`);
    }
    return key;
}
export function importPublicKey(b64) {
    const derBytes = decodeStrictBase64(b64);
    const key = createPublicKey({ key: derBytes, format: "der", type: "spki" });
    if (!key.export({ type: "spki", format: "der" }).equals(derBytes)) {
        throw new Error("Clave pública con DER no canónico");
    }
    return key;
}
export function importPrivateKey(b64) {
    const derBytes = decodeStrictBase64(b64);
    const key = createPrivateKey({ key: derBytes, format: "der", type: "pkcs8" });
    if (!key.export({ type: "pkcs8", format: "der" }).equals(derBytes)) {
        throw new Error("Clave privada con DER no canónico");
    }
    return key;
}
/* ---------------- ML-DSA-87 (firmas de bloque) ---------------- */
export function generateMlDsa87() {
    return exportPair(generateKeyPairSync("ml-dsa-87"));
}
/** ¿Es esta cadena una clave pública ML-DSA-87 SPKI canónica estricta? */
export function isMlDsa87PublicKey(b64) {
    try {
        importPublicKeyStrict(b64, OID_CONTENT.ML_DSA_87, ML_DSA_87_PUBLIC_KEY_BYTES, "ML-DSA-87");
        return true;
    }
    catch {
        return false;
    }
}
/** ¿Es esta cadena una clave pública SLH-DSA-SHAKE-256s SPKI canónica estricta? */
export function isSlhDsaShake256sPublicKey(b64) {
    try {
        importPublicKeyStrict(b64, OID_CONTENT.SLH_DSA_SHAKE_256S, SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES, "SLH-DSA-SHAKE-256s");
        return true;
    }
    catch {
        return false;
    }
}
export function signMlDsa87(privateKeyB64, data) {
    return sign(null, Buffer.from(data), importPrivateKey(privateKeyB64));
}
export function verifyMlDsa87(publicKeyB64, data, signature) {
    try {
        if (signature.length !== ML_DSA_87_SIGNATURE_BYTES)
            return false;
        const key = importPublicKeyStrict(publicKeyB64, OID_CONTENT.ML_DSA_87, ML_DSA_87_PUBLIC_KEY_BYTES, "ML-DSA-87");
        return verify(null, Buffer.from(data), key, Buffer.from(signature));
    }
    catch {
        return false;
    }
}
/* ---------------- SLH-DSA-SHAKE-256s (checkpoints) ---------------- */
export const SLH_DSA_SHAKE_256S_SUPPORTED = (() => {
    try {
        generateKeyPairSync("slh-dsa-shake-256s");
        return true;
    }
    catch {
        return false;
    }
})();
export function generateSlhDsaShake256s() {
    return exportPair(generateKeyPairSync("slh-dsa-shake-256s"));
}
export function signSlhDsaShake256s(privateKeyB64, data) {
    return sign(null, Buffer.from(data), importPrivateKey(privateKeyB64));
}
export function verifySlhDsaShake256s(publicKeyB64, data, signature) {
    try {
        if (signature.length !== SLH_DSA_SHAKE_256S_SIGNATURE_BYTES)
            return false;
        const key = importPublicKeyStrict(publicKeyB64, OID_CONTENT.SLH_DSA_SHAKE_256S, SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES, "SLH-DSA-SHAKE-256s");
        return verify(null, Buffer.from(data), key, Buffer.from(signature));
    }
    catch {
        return false;
    }
}
/* ---------------- ML-KEM-1024 (identidad privada) ---------------- */
export function generateMlKem1024() {
    return exportPair(generateKeyPairSync("ml-kem-1024"));
}
/* --- Validación normativa de la ek ML-KEM-1024 (FIPS 203) — R5.3 ---
 *
 * La ek de ML-KEM-1024 son 1.568 bytes: ByteEncode₁₂(t̂) ‖ ρ, donde t̂ son
 * k = 4 polinomios de 256 coeficientes codificados a 12 bits (1.536
 * bytes) y ρ son 32 bytes arbitrarios (semilla pública). FIPS 203 exige
 * en la encapsulación la comprobación de módulo sobre la codificación:
 * cada coeficiente de 12 bits decodificado debe ser < q = 3329. Una
 * codificación con algún coeficiente ≥ q NO es la salida de ningún
 * ByteEncode₁₂ canónico (que reduce mod q antes de codificar): es una ek
 * no canónica y se rechaza ANTES de encapsular.
 *
 * Qué demuestra este check y qué NO (declaración honesta, hueco KEM-K7b):
 *  - SÍ demuestra: longitud exacta, forma DER/SPKI canónica (capa previa)
 *    y canonicidad de formato según FIPS 203 de la parte polinómica.
 *  - NO demuestra: que la ek provenga de un KeyGen legítimo. Una ek con
 *    coeficientes arbitrarios < q es formalmente indistinguible de una
 *    legítima sin la dk correspondiente; ninguna «prueba algebraica»
 *    casera se finge aquí. El check cierra la clase de eks NO CANÓNICAS
 *    (coeficientes ≥ q), no la de eks ajenas bien formadas.
 */
export const ML_KEM_Q = 3329;
/** Bytes de ByteEncode₁₂(t̂) dentro de la ek: 4 × 256 coeficientes × 12 bits. */
export const ML_KEM_1024_EK_T_BYTES = 1536;
/** Coeficiente nº j (0..1023) del ByteEncode₁₂ de t̂: pares little-endian de 12 bits. */
function byteDecode12Coefficient(t, j) {
    const i = (j >> 1) * 3;
    if ((j & 1) === 0) {
        return t[i] | ((t[i + 1] & 0x0f) << 8);
    }
    return (t[i + 1] >> 4) | (t[i + 2] << 4);
}
/**
 * Validación normativa DISPONIBLE de una ek ML-KEM-1024 cruda (1.568 B):
 * longitud exacta y los 1.024 coeficientes de t̂ (ByteDecode₁₂ de los
 * primeros 1.536 bytes) todos < q = 3329. Los 32 bytes de ρ no llevan
 * restricción (son una semilla arbitraria por especificación).
 */
export function validateMlKem1024Ek(raw) {
    if (raw.length !== ML_KEM_1024_PUBLIC_KEY_BYTES)
        return false;
    const buf = Buffer.from(raw);
    for (let j = 0; j < 1024; j++) {
        if (byteDecode12Coefficient(buf, j) >= ML_KEM_Q)
            return false;
    }
    return true;
}
/** Importación estricta de ek ML-KEM-1024: DER canónico + FIPS 203 (§ de arriba). */
function importMlKem1024PublicKey(b64) {
    const derBytes = decodeStrictBase64(b64);
    const raw = parseSpkiRawKey(derBytes, OID_CONTENT.ML_KEM_1024);
    if (!raw || raw.length !== ML_KEM_1024_PUBLIC_KEY_BYTES) {
        throw new Error("Clave pública ML-KEM-1024 no canónica o de longitud inesperada");
    }
    if (!validateMlKem1024Ek(raw)) {
        throw new Error("Clave pública ML-KEM-1024 no canónica según FIPS 203: algún coeficiente de t̂ (ByteEncode₁₂) es ≥ q = 3329");
    }
    const key = createPublicKey({ key: derBytes, format: "der", type: "spki" });
    if (!key.export({ type: "spki", format: "der" }).equals(derBytes)) {
        throw new Error("Clave pública ML-KEM-1024 con DER no canónico");
    }
    return key;
}
export function kemEncapsulate(publicKeyB64) {
    const key = importMlKem1024PublicKey(publicKeyB64);
    const enc = encapsulate(key);
    return { sharedKey: Buffer.from(enc.sharedKey), ciphertext: Buffer.from(enc.ciphertext) };
}
export function kemDecapsulate(privateKeyB64, ciphertext) {
    if (ciphertext.length !== ML_KEM_1024_CIPHERTEXT_BYTES) {
        throw new Error("Texto cifrado ML-KEM-1024 de longitud inesperada");
    }
    return Buffer.from(decapsulate(importPrivateKey(privateKeyB64), Buffer.from(ciphertext)));
}
