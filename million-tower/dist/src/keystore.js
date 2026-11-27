/**
 * MT-KEYSTORE — Custodia de claves de validador con cifrado en reposo
 * detrás de una interfaz (MOTOR 2 — endurecimiento §12.6 de
 * EVIDENCIA-PQ-consenso-formal.md).
 *
 * ESPECIFICACIÓN.
 *
 * Modelo de amenaza (el declarado en §12.6): los ficheros
 * MT-VALIDATOR-KEY-1 guardan la clave privada PKCS#8 en base64 SIN
 * CIFRAR en el directorio del conjunto; quien los extrae reclasifica
 * la identidad como bizantina (§9.3, fila 8). La postura histórica es
 * «testnet declarada»: las claves no valen nada fuera de esta red.
 * Este módulo NO cambia esa postura por defecto; la hace EXPLÍCITA y
 * añade el modo que la supera:
 *
 *  - protection "plain" (defecto, modo testnet explícito): el fichero
 *    es byte a byte el MT-VALIDATOR-KEY-1 de siempre. Elegirlo es una
 *    decisión declarada, no un descuido: el formato lleva su aviso.
 *  - protection "encrypted" (modo disponible y probado): el fichero es
 *    MT-VALIDATOR-KEY-2 — la clave pública sigue en claro (es pública)
 *    y la privada viaja cifrada con AES-256-GCM bajo una clave de
 *    256 bits derivada de la frase de paso con scrypt
 *    (N=32768, r=8, p=1, sal aleatoria de 32 bytes por fichero; nonce
 *    GCM aleatorio de 12 bytes; texto cifrado ‖ tag de 16 bytes, la
 *    misma convención que el sobre de identidad de la cadena). Sin la
 *    frase de paso correcta el descifrado falla la verificación GCM:
 *    KEYSTORE_DECRYPT_FAILED, sin oráculo de relleno ni de formato.
 *
 * La interfaz KeyCustodyCodec es la puerta ÚNICA de lectura/escritura
 * de ficheros de clave de validador: ValidatorSet.loadOrCreate y el
 * proceso validatornet leen SIEMPRE por decodeValidatorKeyFile (que
 * despacha por el campo format) y escriben por el códec del modo
 * elegido. La frase de paso NUNCA se persiste: llega por opción de
 * carga (proceso en memoria) o por la variable de entorno
 * MT_VALIDATOR_KEY_PASSPHRASE en los procesos validadores.
 *
 * Lo que este módulo NO hace (fuera de alcance, declarado):
 *  - custodia en hardware (R7-HARDWARE) ni gestión/rotación de frases
 *    de paso: son responsabilidad del operador;
 *  - cifrar las OTRAS superficies con claves en claro del árbol: las
 *    claves del archivo de cadena (chain.json: validador local KEM/DSA
 *    de testnet) y los ficheros del keyring de cartera (MT-WALLET).
 *    El mismo códec las cubre mecánicamente cuando la casa lo decida;
 *    quedan nombradas en el informe de Motor 2 como pendientes.
 *
 * REMEDIACIÓN FUZZ-1 (adjudicación de la casa sobre el fuzzing M3) —
 * tres piezas de especificación que este módulo fija:
 *
 *  (a) POLÍTICA SCRYPT DEL FORMATO (Q2 · REM-FZ-05/06). Las cotas de
 *    aceptación de los parámetros kdf que un fichero KEY-2 declara
 *    son UNA política de código con nombre — la constante
 *    SCRYPT_FILE_POLICY de este módulo, y ningún otro literal de cota
 *    de aceptación vive en el módulo —: N potencia de dos en
 *    [2^10, 2^20], r en [1, 32], p en [1, 8] y coste N·r·p ≤ 2^22.
 *    Ningún campo —firmado o no— las mueve: cambiarlas es un cambio
 *    de código auditado, no un dato del fichero. Las combinaciones
 *    dentro de cota pero no ejecutables (memoria) se rechazan
 *    igualmente bajo KEYSTORE_FORMAT_INVALID al derivar. Y la
 *    precedencia es de código (REM-FZ-06): la autenticación decide
 *    la integridad, nunca la política — un fichero íntegro y
 *    atestiguado con parámetros fuera de política se rechaza por la
 *    cota igual que uno sin firmar.
 *
 *  (b) INVENTARIO CERRADO DE CAMPOS (REM-FZ-04). Todo campo que un
 *    consumidor lee tiene una clase, y ningún campo futuro nace
 *    creído:
 *     - KEY-1: `format` — constante del formato, por igualdad exacta;
 *       `validator_id` — contraste contra el manifiesto anclado
 *       (MT-VALIDATOR-MANIFEST-2, src/validators.ts); `publicKey` y
 *       `privateKey` — ligados entre sí por derivación en el decode
 *       (REM-FZ-03) y la pública además anclada por huella en el
 *       manifiesto; `warning` — inerte declarado (ver (c)).
 *     - KEY-2: `format`, `protection`, `kdf.algo`, `cipher.algo` —
 *       constantes del formato, por igualdad exacta; `kdf.N/r/p` —
 *       acotados por SCRYPT_FILE_POLICY; `kdf.salt`, `cipher.nonce`,
 *       `ciphertext` — longitudes del formato y base64 canónico
 *       estricto; `ciphertext` — lo único que el GCM autentica (la
 *       clave privada); `publicKey` — ligada por derivación desde la
 *       privada descifrada y anclada por huella en el manifiesto;
 *       `validator_id` — contraste del manifiesto; `warning` —
 *       inerte declarado.
 *    Un campo extraño añadido a un fichero se ignora sin efecto o se
 *    rechaza; nunca se interpreta.
 *
 *  (c) `warning` Y TODO TEXTO LIBRE: CAMPO NO AUTENTICADO, SIN
 *    SEMÁNTICA (Q3 · REM-FZ-08). Ninguna ruta de código lo lee para
 *    decidir nada. Sobrevive en la forma histórica KEY-1/KEY-2
 *    porque esa forma está fijada byte a byte (battery24), no porque
 *    signifique algo.
 *
 * Ligadura pública↔privada (REM-FZ-03): AMBOS decodes derivan la
 * clave pública desde la privada (PKCS#8→SPKI) y exigen identidad
 * con la declarada — también el decode en claro, que antes devolvía
 * la declarada sin derivarla. El decode aislado sigue sin opinar
 * sobre la IDENTIDAD del conjunto: eso lo decide el manifiesto
 * anclado (src/validators.ts); quien consuma un decode aislado
 * hereda ese límite y debe decirlo.
 *
 * Dinero real: BLOQUEADO. Todo es testnet.
 */
import { createCipheriv, createDecipheriv, createPrivateKey, createPublicKey, randomBytes, scryptSync } from "node:crypto";
export const VALIDATOR_KEY_PLAIN_FORMAT = "MT-VALIDATOR-KEY-1";
export const VALIDATOR_KEY_ENCRYPTED_FORMAT = "MT-VALIDATOR-KEY-2";
export const VALIDATOR_KEY_PLAIN_WARNING = "TESTNET: clave privada sin valor real. Vive solo en data/validators/ y solo la usa la custodia de su validador.";
export const VALIDATOR_KEY_ENCRYPTED_WARNING = "TESTNET: clave privada CIFRADA en reposo (AES-256-GCM; clave derivada de la frase de paso con scrypt). Sin la frase de paso esta custodia no puede firmar.";
export class KeystoreError extends Error {
    code;
    constructor(code, message) {
        super(message);
        this.code = code;
        this.name = "KeystoreError";
    }
}
const SCRYPT_PARAMS = { N: 32768, r: 8, p: 1 };
const SCRYPT_MAXMEM = 256 * 1024 * 1024;
/**
 * POLÍTICA SCRYPT DEL FORMATO (FUZZ-1 · Q2 · REM-FZ-05): las cotas de
 * ACEPTACIÓN de los parámetros kdf que un fichero MT-VALIDATOR-KEY-2
 * declara. Constante única, nombrada y congelada: ningún otro literal
 * de cota de aceptación vive en el módulo, ningún campo del fichero
 * —firmado o no— la mueve, y cambiarla es un cambio de código
 * auditado. Los parámetros del ENCODE propio (SCRYPT_PARAMS) cumplen
 * esta política pero no forman parte de ella: son la elección fija
 * del escritor, no una cota de aceptación.
 */
export const SCRYPT_FILE_POLICY = Object.freeze({
    N_MIN: 1024,
    N_MAX: 1048576,
    R_MIN: 1,
    R_MAX: 32,
    P_MIN: 1,
    P_MAX: 8,
    COST_MAX: 4194304,
});
const KEY_LEN = 32;
const SALT_LEN = 32;
const NONCE_LEN = 12;
const GCM_TAG_LEN = 16;
function deriveKey(passphrase, salt) {
    return scryptSync(passphrase, salt, KEY_LEN, { ...SCRYPT_PARAMS, maxmem: SCRYPT_MAXMEM });
}
/**
 * Deriva la clave pública (SPKI DER base64) desde la privada (PKCS#8
 * DER base64): la mitad mecánica de la ligadura pública↔privada del
 * decode en claro (REM-FZ-03; el decode cifrado aplica la misma
 * derivación en línea tras el GCM, con sus textos propios). Una
 * privada que no parsea como PKCS#8 es KEYSTORE_DECRYPT_FAILED — el
 * código de «material incoherente o alterado», sin oráculo de
 * formato.
 */
function derivePublicKeyB64(privateKeyB64) {
    try {
        return createPublicKey(createPrivateKey({ key: Buffer.from(privateKeyB64, "base64"), format: "der", type: "pkcs8" }))
            .export({ type: "spki", format: "der" })
            .toString("base64");
    }
    catch {
        throw new KeystoreError("KEYSTORE_DECRYPT_FAILED", "La clave privada del fichero no es un PKCS#8 válido");
    }
}
export const plainKeyCustody = {
    protection: "plain",
    encode(material) {
        const file = {
            format: VALIDATOR_KEY_PLAIN_FORMAT,
            warning: VALIDATOR_KEY_PLAIN_WARNING,
            validator_id: material.validator_id,
            publicKey: material.publicKey,
            privateKey: material.privateKey,
        };
        return JSON.stringify(file, null, 2) + "\n";
    },
    decode(contents) {
        const file = parseKeyFile(contents);
        if (file.format !== VALIDATOR_KEY_PLAIN_FORMAT) {
            throw new KeystoreError("KEYSTORE_FORMAT_MISMATCH", `El códec en claro solo lee ${VALIDATOR_KEY_PLAIN_FORMAT}; el fichero declara ${String(file.format)}`);
        }
        const validator_id = requireString(file, "validator_id");
        const publicKey = requireString(file, "publicKey");
        const privateKey = requireString(file, "privateKey");
        /* Ligadura pública↔privada TAMBIÉN en claro (FUZZ-1 · REM-FZ-03):
         * este decode devolvía la pública declarada sin derivarla — un
         * fichero KEY-1 con la pública sustituida decodificaba «bien» con
         * material incoherente, y la identidad solo la rescataba el
         * contraste posterior de loadOrCreate —. Ahora se deriva la
         * pública desde la privada y se exige identidad, la misma
         * ligadura que el decode cifrado aplica tras el GCM. Cambia el
         * COMPORTAMIENTO del decode, no la forma del fichero: ni un byte
         * del encode histórico se mueve. */
        if (derivePublicKeyB64(privateKey) !== publicKey) {
            throw new KeystoreError("KEYSTORE_DECRYPT_FAILED", "La clave pública declarada en el fichero no corresponde a su clave privada");
        }
        return {
            validator_id,
            publicKey,
            privateKey,
            format: VALIDATOR_KEY_PLAIN_FORMAT,
            protection: "plain",
        };
    },
};
export const encryptedKeyCustody = {
    protection: "encrypted",
    encode(material, passphrase) {
        if (!passphrase) {
            throw new KeystoreError("KEYSTORE_PASSPHRASE_REQUIRED", "El modo cifrado exige una frase de paso para sellar la clave privada");
        }
        const salt = randomBytes(SALT_LEN);
        const nonce = randomBytes(NONCE_LEN);
        const key = deriveKey(passphrase, salt);
        const cipher = createCipheriv("aes-256-gcm", key, nonce);
        const encrypted = Buffer.concat([
            cipher.update(Buffer.from(material.privateKey, "utf8")),
            cipher.final(),
        ]);
        const ciphertext = Buffer.concat([encrypted, cipher.getAuthTag()]);
        const file = {
            format: VALIDATOR_KEY_ENCRYPTED_FORMAT,
            warning: VALIDATOR_KEY_ENCRYPTED_WARNING,
            validator_id: material.validator_id,
            publicKey: material.publicKey,
            protection: "scrypt-aes-256-gcm",
            kdf: { algo: "scrypt", ...SCRYPT_PARAMS, salt: salt.toString("base64") },
            cipher: { algo: "AES-256-GCM", nonce: nonce.toString("base64") },
            ciphertext: ciphertext.toString("base64"),
        };
        return JSON.stringify(file, null, 2) + "\n";
    },
    decode(contents, passphrase) {
        const file = parseKeyFile(contents);
        if (file.format !== VALIDATOR_KEY_ENCRYPTED_FORMAT) {
            throw new KeystoreError("KEYSTORE_FORMAT_MISMATCH", `El códec cifrado solo lee ${VALIDATOR_KEY_ENCRYPTED_FORMAT}; el fichero declara ${String(file.format)}`);
        }
        if (!passphrase) {
            throw new KeystoreError("KEYSTORE_PASSPHRASE_REQUIRED", "El fichero de clave está cifrado (MT-VALIDATOR-KEY-2) y no se aportó frase de paso");
        }
        const kdf = file.kdf;
        const cipherInfo = file.cipher;
        if (!kdf || typeof kdf.salt !== "string" ||
            !cipherInfo || typeof cipherInfo.nonce !== "string" ||
            typeof file.ciphertext !== "string") {
            throw new KeystoreError("KEYSTORE_FORMAT_INVALID", "El fichero MT-VALIDATOR-KEY-2 está incompleto (kdf/cipher/ciphertext)");
        }
        /* --- Endurecimiento M3-FUZZ (parche en copia, pendiente de porte) ---
         * Los campos declarativos del fichero se COMPRUEBAN, no se ignoran:
         * un fichero que declara otros algoritmos, otros parámetros fuera de
         * cota o representaciones base64 no canónicas se rechaza ANTES de
         * derivar. Antes: kdf.algo/cipher.algo/protection no se leían, N/r/p
         * presentes con tipo erróneo caían en silencio al valor por defecto,
         * y p/N del fichero no tenían cota alguna (p=512 ⇒ minutos de CPU en
         * cada intento de carga: DoS por fichero). */
        if (kdf.algo !== "scrypt" ||
            cipherInfo.algo !== "AES-256-GCM" ||
            file.protection !== "scrypt-aes-256-gcm") {
            throw new KeystoreError("KEYSTORE_FORMAT_INVALID", "El fichero MT-VALIDATOR-KEY-2 declara algoritmos o protección distintos de los del formato (scrypt / AES-256-GCM)");
        }
        const strictB64 = (s, what) => {
            const b = Buffer.from(s, "base64");
            if (b.toString("base64") !== s) {
                throw new KeystoreError("KEYSTORE_FORMAT_INVALID", `El campo ${what} del fichero MT-VALIDATOR-KEY-2 no es base64 canónico`);
            }
            return b;
        };
        const param = (v, name, min, max) => {
            if (typeof v !== "number" || !Number.isInteger(v) || v < min || v > max) {
                throw new KeystoreError("KEYSTORE_FORMAT_INVALID", `El parámetro scrypt ${name} del fichero MT-VALIDATOR-KEY-2 falta o está fuera de cota [${min}..${max}]`);
            }
            return v;
        };
        const N = param(kdf.N, "N", SCRYPT_FILE_POLICY.N_MIN, SCRYPT_FILE_POLICY.N_MAX);
        if ((N & (N - 1)) !== 0) {
            throw new KeystoreError("KEYSTORE_FORMAT_INVALID", "El parámetro scrypt N del fichero MT-VALIDATOR-KEY-2 no es potencia de dos");
        }
        const r = param(kdf.r, "r", SCRYPT_FILE_POLICY.R_MIN, SCRYPT_FILE_POLICY.R_MAX);
        const p = param(kdf.p, "p", SCRYPT_FILE_POLICY.P_MIN, SCRYPT_FILE_POLICY.P_MAX);
        if (N * r * p > SCRYPT_FILE_POLICY.COST_MAX) {
            throw new KeystoreError("KEYSTORE_FORMAT_INVALID", "El coste scrypt declarado por el fichero MT-VALIDATOR-KEY-2 excede la cota del formato");
        }
        const salt = strictB64(kdf.salt, "kdf.salt");
        if (salt.length < 16 || salt.length > 64) {
            throw new KeystoreError("KEYSTORE_FORMAT_INVALID", "La sal del fichero MT-VALIDATOR-KEY-2 tiene una longitud fuera de cota");
        }
        const nonce = strictB64(cipherInfo.nonce, "cipher.nonce");
        if (nonce.length !== NONCE_LEN) {
            throw new KeystoreError("KEYSTORE_FORMAT_INVALID", "El nonce del fichero MT-VALIDATOR-KEY-2 no mide 12 bytes");
        }
        const blob = strictB64(file.ciphertext, "ciphertext");
        if (blob.length <= GCM_TAG_LEN) {
            throw new KeystoreError("KEYSTORE_FORMAT_INVALID", "El texto cifrado del fichero MT-VALIDATOR-KEY-2 es demasiado corto");
        }
        let key;
        try {
            key = scryptSync(passphrase, salt, KEY_LEN, { N, r, p, maxmem: SCRYPT_MAXMEM });
        }
        catch {
            throw new KeystoreError("KEYSTORE_FORMAT_INVALID", "Los parámetros scrypt del fichero MT-VALIDATOR-KEY-2 no son ejecutables");
        }
        const decipher = createDecipheriv("aes-256-gcm", key, nonce);
        decipher.setAuthTag(blob.subarray(blob.length - GCM_TAG_LEN));
        let privateKey;
        try {
            privateKey = Buffer.concat([
                decipher.update(blob.subarray(0, blob.length - GCM_TAG_LEN)),
                decipher.final(),
            ]).toString("utf8");
        }
        catch {
            // GCM no distingue «frase de paso errónea» de «fichero alterado»:
            // un solo código estable para ambos, sin oráculo.
            throw new KeystoreError("KEYSTORE_DECRYPT_FAILED", "No se pudo descifrar la clave privada: frase de paso incorrecta o fichero alterado");
        }
        /* La clave pública en claro del fichero NO la cubre el GCM (que solo
         * autentica la privada): sin este cruce, un fichero alterado en su
         * publicKey decodificaba «bien» devolviendo un material incoherente
         * (218/300 mutaciones de esa región pasaban en el fuzzing M3). Se
         * deriva la pública de la privada descifrada y se exige identidad. */
        const declaredPublic = requireString(file, "publicKey");
        let derivedPublic;
        try {
            derivedPublic = createPublicKey(createPrivateKey({ key: Buffer.from(privateKey, "base64"), format: "der", type: "pkcs8" }))
                .export({ type: "spki", format: "der" })
                .toString("base64");
        }
        catch {
            throw new KeystoreError("KEYSTORE_DECRYPT_FAILED", "La clave privada descifrada no es un PKCS#8 válido");
        }
        if (derivedPublic !== declaredPublic) {
            throw new KeystoreError("KEYSTORE_DECRYPT_FAILED", "La clave pública declarada en el fichero no corresponde a la clave privada descifrada");
        }
        return {
            validator_id: requireString(file, "validator_id"),
            publicKey: declaredPublic,
            privateKey,
            format: VALIDATOR_KEY_ENCRYPTED_FORMAT,
            protection: "encrypted",
        };
    },
};
/** El códec de un modo de protección (la puerta de escritura). */
export function keyCustodyFor(protection) {
    return protection === "encrypted" ? encryptedKeyCustody : plainKeyCustody;
}
/**
 * La puerta de LECTURA: despacha por el campo format del fichero
 * (KEY-1 en claro, KEY-2 cifrado). Cualquier otro formato se rechaza
 * con KEYSTORE_FORMAT_UNKNOWN — nunca se adivina un modo.
 */
export function decodeValidatorKeyFile(contents, passphrase) {
    const file = parseKeyFile(contents);
    if (file.format === VALIDATOR_KEY_PLAIN_FORMAT)
        return plainKeyCustody.decode(contents);
    if (file.format === VALIDATOR_KEY_ENCRYPTED_FORMAT)
        return encryptedKeyCustody.decode(contents, passphrase);
    throw new KeystoreError("KEYSTORE_FORMAT_UNKNOWN", `Formato de fichero de clave no reconocido: ${String(file.format)}`);
}
function parseKeyFile(contents) {
    let parsed;
    try {
        parsed = JSON.parse(contents);
    }
    catch {
        throw new KeystoreError("KEYSTORE_FORMAT_INVALID", "El fichero de clave no es JSON válido");
    }
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new KeystoreError("KEYSTORE_FORMAT_INVALID", "El fichero de clave no es un objeto JSON");
    }
    return parsed;
}
function requireString(file, field) {
    const v = file[field];
    if (typeof v !== "string" || v.length === 0) {
        throw new KeystoreError("KEYSTORE_FORMAT_INVALID", `El fichero de clave no trae el campo ${field}`);
    }
    return v;
}
