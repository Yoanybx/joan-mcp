/**
 * MT-ULTRA-1 · Huella de bloque: MT-DUAL-1024
 * MT-DUAL-1024(data) = hex(SHA3-512(input)) ‖ hex(SHA-512(input))  → 256 caracteres hex.
 * Separación de dominio: si se pasa `domain`, el input efectivo es
 *   utf8("MT-DUAL-1024|" + domain + "|") ‖ data
 * y ese mismo input alimenta AMBOS hashes (el dominio nunca se hashea por separado).
 *
 * Nota honesta (fallo V1.2): una salida de 1.024 bits NO es "1.024 bits de seguridad";
 * es margen de huella por defensa en profundidad sobre dos familias de hash.
 */
import { createHash } from "node:crypto";
function toBytes(data) {
    return typeof data === "string" ? Buffer.from(data, "utf8") : Buffer.from(data);
}
export function domainInput(data, domain) {
    const bytes = toBytes(data);
    if (!domain)
        return bytes;
    return Buffer.concat([Buffer.from(`MT-DUAL-1024|${domain}|`, "utf8"), bytes]);
}
export function sha3_512Hex(data, domain) {
    return createHash("sha3-512").update(domainInput(data, domain)).digest("hex");
}
export function sha512Hex(data, domain) {
    return createHash("sha512").update(domainInput(data, domain)).digest("hex");
}
/** MT-DUAL-1024: 128 hex (SHA3-512) ‖ 128 hex (SHA-512) = 256 caracteres hex. */
export function mtDual1024(data, domain) {
    const input = domainInput(data, domain);
    const a = createHash("sha3-512").update(input).digest("hex");
    const b = createHash("sha512").update(input).digest("hex");
    return a + b;
}
export const ZERO_HASH_1024 = "0".repeat(256);
