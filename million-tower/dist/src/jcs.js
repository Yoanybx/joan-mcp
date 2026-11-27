/**
 * Canonicalización JSON según RFC 8785 (JCS) — subconjunto cerrado del proyecto:
 *  - Objetos: claves ordenadas por unidades de código UTF-16 (regla RFC 8785).
 *  - Strings: escape idéntico a JSON.stringify de ECMAScript (base del RFC).
 *  - Números: SOLO enteros seguros (|n| <= 2^53-1). Los flotantes — y en
 *    particular cualquier importe monetario no entero — se RECHAZAN.
 *  - Claves duplicadas: imposibles en un objeto JS ya parseado, por lo que la
 *    API de texto (`parseStrictJson`) usa un parser propio que las detecta y
 *    rechaza la entrada completa. Nada se corrige en silencio.
 *  - Conformidades restauradas por ADJUDICACION-H-A8-05 (la batería
 *    dedicada battery-jcs cazó las cuatro divergencias; la casa falló
 *    arreglarlas todas):
 *    · D-JCS-01: la vía estricta RECHAZA toda clave que no sobreviva a la
 *      asignación como propiedad propia (`__proto__`) con JCS_FORBIDDEN_KEY
 *      — nunca se pierde en silencio ni colisiona con el objeto vacío.
 *    · D-JCS-02: un surrogado solitario termina con error
 *      (JCS_LONE_SURROGATE), como manda RFC 8785 §3.2.2.2 — no se escapa.
 *    · D-JCS-03: los ceros a la izquierda (`01`, `-01`, `00`) se rechazan
 *      en el parser estricto, conforme a la gramática de RFC 8259.
 *    · D-JCS-04: `canonicalize` solo admite objetos PLANOS (prototipo
 *      Object.prototype o nulo); Date, Map o cualquier instancia lanzan
 *      JCS_UNSUPPORTED_VALUE en vez de canonicalizar a "{}" en silencio.
 */
export class JcsError extends Error {
    code;
    constructor(code, message) {
        super(message);
        this.code = code;
        this.name = "JcsError";
    }
}
function escapeString(s) {
    let out = '"';
    for (let i = 0; i < s.length; i++) {
        const c = s.charCodeAt(i);
        if (c === 0x22)
            out += '\\"';
        else if (c === 0x5c)
            out += "\\\\";
        else if (c === 0x08)
            out += "\\b";
        else if (c === 0x09)
            out += "\\t";
        else if (c === 0x0a)
            out += "\\n";
        else if (c === 0x0c)
            out += "\\f";
        else if (c === 0x0d)
            out += "\\r";
        else if (c < 0x20)
            out += "\\u" + c.toString(16).padStart(4, "0");
        else if (c >= 0xd800 && c <= 0xdbff) {
            const next = i + 1 < s.length ? s.charCodeAt(i + 1) : 0;
            if (next >= 0xdc00 && next <= 0xdfff) {
                out += s[i] + s[i + 1];
                i++;
            }
            else {
                // D-JCS-02 (ADJUDICACION-H-A8-05): RFC 8785 §3.2.2.2 — la
                // serialización de un surrogado solitario MUST terminar con error;
                // no se escapa como hacía JSON.stringify bien formado.
                throw new JcsError("JCS_LONE_SURROGATE", "Surrogado alto sin pareja de surrogado bajo: RFC 8785 §3.2.2.2 exige terminar con error");
            }
        }
        else if (c >= 0xdc00 && c <= 0xdfff) {
            throw new JcsError("JCS_LONE_SURROGATE", "Surrogado bajo sin pareja de surrogado alto: RFC 8785 §3.2.2.2 exige terminar con error");
        }
        else {
            out += s[i];
        }
    }
    return out + '"';
}
/** Serializa un valor ya en memoria a su forma canónica JCS (subconjunto entero). */
export function canonicalize(value) {
    if (value === null)
        return "null";
    if (value === true)
        return "true";
    if (value === false)
        return "false";
    if (typeof value === "number") {
        if (!Number.isSafeInteger(value)) {
            throw new JcsError("JCS_NON_INTEGER_NUMBER", `JCS de MILLION TOWER solo admite enteros seguros; recibido: ${value}`);
        }
        return String(value); // -0 se serializa como "0", como exige el RFC
    }
    if (typeof value === "string")
        return escapeString(value);
    if (Array.isArray(value)) {
        const parts = [];
        for (const el of value) {
            if (el === undefined || typeof el === "function" || typeof el === "symbol") {
                throw new JcsError("JCS_UNSUPPORTED_VALUE", "Valor no serializable dentro de un array JCS");
            }
            parts.push(canonicalize(el));
        }
        return "[" + parts.join(",") + "]";
    }
    if (typeof value === "object") {
        // D-JCS-04 (ADJUDICACION-H-A8-05): solo objetos planos. Un Date, un Map
        // o cualquier instancia de clase no tiene claves JSON propias que
        // canonicalizar: antes devolvía "{}" en silencio; ahora lanza.
        const proto = Object.getPrototypeOf(value);
        if (proto !== Object.prototype && proto !== null) {
            throw new JcsError("JCS_UNSUPPORTED_VALUE", `Objeto no plano no admitido en JCS (solo objetos JSON): ${Object.prototype.toString.call(value)}`);
        }
        const obj = value;
        const keys = Object.keys(obj).sort(); // orden por unidades UTF-16 (defecto de sort en JS)
        const parts = [];
        for (const k of keys) {
            const v = obj[k];
            if (v === undefined || typeof v === "function" || typeof v === "symbol") {
                throw new JcsError("JCS_UNSUPPORTED_VALUE", `Valor no serializable en la clave "${k}"`);
            }
            parts.push(escapeString(k) + ":" + canonicalize(v));
        }
        return "{" + parts.join(",") + "}";
    }
    throw new JcsError("JCS_UNSUPPORTED_VALUE", `Tipo no admitido en JCS: ${typeof value}`);
}
export function canonicalBytes(value) {
    return Buffer.from(canonicalize(value), "utf8");
}
/**
 * Parser JSON estricto para entradas externas: detecta claves duplicadas
 * (JCS_DUPLICATE_KEY) y rechaza números no enteros (JCS_NON_INTEGER_NUMBER).
 * Devuelve el valor parseado, listo para `canonicalize`.
 */
export function parseStrictJson(text) {
    let pos = 0;
    const len = text.length;
    function fail(code, msg) {
        throw new JcsError(code, `${msg} (posición ${pos})`);
    }
    function skipWs() {
        while (pos < len) {
            const c = text.charCodeAt(pos);
            if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d)
                pos++;
            else
                break;
        }
    }
    function parseString() {
        // text[pos] === '"'
        pos++;
        let out = "";
        while (pos < len) {
            const c = text.charCodeAt(pos);
            if (c === 0x22) {
                pos++;
                return out;
            }
            if (c === 0x5c) {
                pos++;
                if (pos >= len)
                    fail("JCS_INVALID_JSON", "Escape incompleto");
                const e = text[pos];
                if (e === '"')
                    out += '"';
                else if (e === "\\")
                    out += "\\";
                else if (e === "/")
                    out += "/";
                else if (e === "b")
                    out += "\b";
                else if (e === "f")
                    out += "\f";
                else if (e === "n")
                    out += "\n";
                else if (e === "r")
                    out += "\r";
                else if (e === "t")
                    out += "\t";
                else if (e === "u") {
                    const hex = text.slice(pos + 1, pos + 5);
                    if (!/^[0-9a-fA-F]{4}$/.test(hex))
                        fail("JCS_INVALID_JSON", "Escape \\u inválido");
                    out += String.fromCharCode(parseInt(hex, 16));
                    pos += 4;
                }
                else {
                    fail("JCS_INVALID_JSON", `Escape no válido: \\${e}`);
                }
                pos++;
                continue;
            }
            if (c < 0x20)
                fail("JCS_INVALID_JSON", "Carácter de control sin escapar en string");
            out += text[pos];
            pos++;
        }
        fail("JCS_INVALID_JSON", "String sin cerrar");
    }
    function parseNumber() {
        const start = pos;
        if (text[pos] === "-")
            pos++;
        // D-JCS-03 (ADJUDICACION-H-A8-05): la gramática de RFC 8259 no admite
        // ceros a la izquierda — un «0» inicial no puede ir seguido de dígitos
        // ("01", "-01", "00" se rechazan, como hace JSON.parse).
        if (text[pos] === "0" && pos + 1 < len && text[pos + 1] >= "0" && text[pos + 1] <= "9") {
            fail("JCS_INVALID_JSON", "Número con cero a la izquierda, prohibido por RFC 8259");
        }
        while (pos < len && text[pos] >= "0" && text[pos] <= "9")
            pos++;
        let isFloat = false;
        if (text[pos] === ".") {
            isFloat = true;
            pos++;
            while (pos < len && text[pos] >= "0" && text[pos] <= "9")
                pos++;
        }
        if (text[pos] === "e" || text[pos] === "E") {
            isFloat = true;
            pos++;
            if (text[pos] === "+" || text[pos] === "-")
                pos++;
            while (pos < len && text[pos] >= "0" && text[pos] <= "9")
                pos++;
        }
        const raw = text.slice(start, pos);
        const n = Number(raw);
        if (raw === "" || raw === "-" || Number.isNaN(n))
            fail("JCS_INVALID_JSON", `Número inválido: "${raw}"`);
        if (isFloat || !Number.isSafeInteger(n)) {
            fail("JCS_NON_INTEGER_NUMBER", `Número no entero seguro rechazado: "${raw}"`);
        }
        return n;
    }
    function parseValue() {
        skipWs();
        if (pos >= len)
            fail("JCS_INVALID_JSON", "Fin inesperado");
        const c = text[pos];
        if (c === "{") {
            pos++;
            const obj = {};
            const seen = new Set();
            skipWs();
            if (text[pos] === "}") {
                pos++;
                return obj;
            }
            for (;;) {
                skipWs();
                if (text[pos] !== '"')
                    fail("JCS_INVALID_JSON", "Se esperaba una clave string");
                const key = parseString();
                if (seen.has(key))
                    fail("JCS_DUPLICATE_KEY", `Clave duplicada rechazada: "${key}"`);
                seen.add(key);
                skipWs();
                if (text[pos] !== ":")
                    fail("JCS_INVALID_JSON", "Se esperaba ':'");
                pos++;
                const parsed = parseValue();
                obj[key] = parsed;
                // D-JCS-01 (ADJUDICACION-H-A8-05): la asignación `obj["__proto__"]=v`
                // fija el PROTOTIPO en vez de crear la propiedad, y la clave se
                // perdía en silencio ('{"__proto__":1}' canonicalizaba a "{}",
                // colisión exacta con el objeto vacío). Toda clave que no
                // sobreviva como propiedad propia se RECHAZA con error nombrado.
                if (!Object.prototype.hasOwnProperty.call(obj, key)) {
                    fail("JCS_FORBIDDEN_KEY", `Clave rechazada: no sobrevive como propiedad propia: "${key}"`);
                }
                skipWs();
                if (text[pos] === ",") {
                    pos++;
                    continue;
                }
                if (text[pos] === "}") {
                    pos++;
                    return obj;
                }
                fail("JCS_INVALID_JSON", "Se esperaba ',' o '}'");
            }
        }
        if (c === "[") {
            pos++;
            const arr = [];
            skipWs();
            if (text[pos] === "]") {
                pos++;
                return arr;
            }
            for (;;) {
                arr.push(parseValue());
                skipWs();
                if (text[pos] === ",") {
                    pos++;
                    continue;
                }
                if (text[pos] === "]") {
                    pos++;
                    return arr;
                }
                fail("JCS_INVALID_JSON", "Se esperaba ',' o ']'");
            }
        }
        if (c === '"')
            return parseString();
        if (text.startsWith("true", pos)) {
            pos += 4;
            return true;
        }
        if (text.startsWith("false", pos)) {
            pos += 5;
            return false;
        }
        if (text.startsWith("null", pos)) {
            pos += 4;
            return null;
        }
        if (c === "-" || (c >= "0" && c <= "9"))
            return parseNumber();
        fail("JCS_INVALID_JSON", `Token inesperado: "${c}"`);
    }
    const value = parseValue();
    skipWs();
    if (pos !== len)
        fail("JCS_INVALID_JSON", "Contenido extra tras el valor JSON");
    return value;
}
