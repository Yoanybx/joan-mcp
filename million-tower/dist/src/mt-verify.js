/**
 * Fase 6 · mt-verify — verificador independiente de pruebas (D-10) — TESTNET.
 *
 * Este verificador NO usa el estado interno de la cadena: no importa
 * src/chain.ts ni src/proof.ts, no lee data/ y no hace red. Trabaja SOLO
 * desde un paquete MT-BRICK-PROOF-1 y los parámetros públicos embebidos en
 * él (manifiesto de validadores y, si viene, la clave del checkpoint). Puede
 * correr offline en otra máquina con el paquete como único insumo.
 *
 * Veredictos:
 *  - VALID:          el paquete está completo y todo verifica.
 *  - INVALID:        el paquete está completo pero algo NO verifica
 *                    (huella constitucional distinta de la anclada, bloque
 *                    alterado, certificado por debajo del quórum, compromiso
 *                    de propiedad o factor de posición que no cuadran…).
 *  - INCOMPLETE:     falta alguna pieza necesaria para decidir (bloques,
 *                    manifiesto, el bloque del sujeto, la clave del
 *                    checkpoint que el paquete declara usar…).
 *  - NOT_VERIFIABLE: ni siquiera se puede intentar (no es un objeto, o el
 *                    formato no es MT-BRICK-PROOF-1).
 *
 * Componentes comprobados (cada uno OK / FAIL / MISSING / SKIPPED):
 *  format, chain_id, constitution_anchor, genesis, validator_manifest,
 *  block_linkage, block_fingerprints, validator_signatures,
 *  finality_certificates, subject_brick, ownership_commitment,
 *  position_factor y —solo si el paquete trae checkpoint— checkpoint_slh_dsa.
 *
 * ANCLA EXTERNA (fase 14, AUD-01): el componente `external_anchor` compara
 * el paquete contra valores publicados FUERA de él (huella constitucional
 * y/o hash del génesis) cuando el llamante los aporta vía `ProofAnchors`.
 * Sin anclas queda SKIPPED y el veredicto VALID significa solo
 * «consistencia interna»: un paquete forjado autoconsistente con la huella
 * pública copiada es internamente válido.
 *
 * CADENA DE MANIFIESTOS ANCLADA (MT-VALIDATOR-MANIFEST-CHAIN-1, cierre
 * estructural de F-A6-01): desde este cierre, el paquete puede traer la
 * cadena de manifiestos de la red (bootstrap externo + manifiestos
 * canónicos + transiciones E-19) en `public_parameters.manifest_chain`.
 * Este verificador la juzga con lógica propia (componentes
 * `validator_manifest_chain`, `validator_manifest_anchor` y
 * `validator_attribution`): esquema cerrado de cada objeto, políticas
 * contrastadas contra la raíz, encadenamiento sin huecos desde H(M0),
 * pruebas de posesión, autorización de cada transición por el quórum de
 * supervivientes del conjunto saliente y la autoridad fría 2-de-3 sobre
 * el mismo tuplo, y certificados juzgados contra el manifiesto VIGENTE
 * en la altura de cada bloque. El manifiesto plano del paquete debe
 * coincidir con el manifiesto vigente de esa cadena: si no coincide, el
 * veredicto es INVALID con el motivo VALIDATOR_MANIFEST_HASH_MISMATCH.
 * ALCANCE EXACTO DE LAS ANCLAS TRAS EL CIERRE: la huella constitucional
 * y el hash del génesis cubren lo que cubrían; la atribución de
 * finalidad queda anclada SOLO cuando el llamante aporta además el
 * ancla del manifiesto inicial (`initial_validator_manifest_hash`,
 * publicada fuera del paquete como parte del bootstrap) y esta
 * coincide con H(M0) de la cadena presentada. Sin esa ancla, la cadena
 * se verifica por dentro (íntegra y encadenada) pero su raíz no está
 * contrastada contra ningún valor externo, y el componente
 * `validator_attribution` lo declara SKIPPED: un VALID así prueba la
 * integridad de la cadena de manifiestos, no su raíz. Un paquete SIN
 * sección de cadena (formato previo al cierre) se sigue verificando
 * como antes, con la atribución declarada no establecida: su manifiesto
 * es autodeclarado y este verificador no lo presenta como anclado.
 * REMEDIACIÓN C-AUD-20 (F-20-01/F-20-05): el llamante puede aportar
 * además `bootstrap_hash` — H(bootstrap) del bootstrap publicado — y
 * entonces el bootstrap ENTERO queda anclado, incluida
 * `finality_activation_height`, que H(M0) no cubre: el componente
 * `bootstrap_anchor` lo contrasta en las tres rutas con anclas
 * (ladrillo, manifiesto y atestación) y su discrepancia es INVALID con
 * degradación de la atribución, como la del ancla inicial (F-ADV-02).
 * Sin esa ancla el componente queda SKIPPED y lo declara: la activación
 * y el resto del contenido del bootstrap se acreditan solo por la
 * consistencia interna de la cadena.
 *
 * Checkpoints (D-12, fase 12): si el paquete trae un checkpoint de estado
 * MT-STATE-CHECKPOINT-1, el componente se verifica de verdad: raíz de
 * bloques Merkle recalculada desde los bloques del paquete, raíz de estado
 * MT-DUAL-1024 recomputada desde sus componentes declarados y firma
 * SLH-DSA-SHAKE-256s sobre el núcleo canónico. La raíz del diario que el
 * checkpoint declara queda atestada por esa firma (el paquete no lleva el
 * diario), no se recomputa aquí. Si el paquete no trae checkpoint, el
 * componente queda SKIPPED, nunca verificado a medias. Los paquetes de
 * baterías antiguas con la forma {root, block_count, signature} siguen
 * verificándose por la vía legada (raíz MT-DUAL-1024 sobre
 * JCS({block_hashes, chain_id}), dominio MT-CHECKPOINT-1).
 *
 * REMEDIACIÓN C-AUD-20 (F-20-02): la ruta de ladrillo aplica desde esta
 * remediación el esquema cerrado también al sobre del paquete, al
 * sujeto y a los parámetros públicos (listas BRICK_PROOF_* de
 * src/schema.ts, derivadas de las interfaces del productor), como ya
 * hacían las rutas de puente y de manifiesto con los suyos.
 *
 * REMEDIACIÓN C-AUD-20 (F-20-03): en la ruta de puente, el paquete de
 * SOLO BLOQUEO (`burn_proof` declarado null: el bloqueo se juzga y el
 * retorno no) ya no sale con veredicto superior VALID: sale INCOMPLETE,
 * en espejo del caso análogo de la ruta de atestación. El componente
 * `burn_proof` sigue SKIPPED —nunca verificado a medias—; lo que se
 * alinea es el veredicto agregado que lee quien no abre componentes.
 */
import { canonicalBytes, canonicalize } from "./jcs.js";
import { mtDual1024, ZERO_HASH_1024 } from "./hash.js";
import { isMlDsa87PublicKey, isSlhDsaShake256sPublicKey, verifyMlDsa87, verifySlhDsaShake256s, } from "./keys.js";
import { firstUnknownField, schemaFieldNotAllowedMessage, BRIDGE_LOCK_PROOF_FIELDS, BRIDGE_PROOF_PACKAGE_FIELDS, BRICK_PROOF_INSCRIPTION_FIELDS, BRICK_PROOF_PACKAGE_FIELDS, BRICK_PROOF_POSITION_FACTOR_PARTS_FIELDS, BRICK_PROOF_PUBLIC_PARAMETERS_FIELDS, BRICK_PROOF_SUBJECT_FIELDS, CANONICAL_MANIFEST_ENTRY_FIELDS, CANONICAL_MANIFEST_FIELDS, COLD_AUTHORITY_FIELDS, COLD_CUSTODIAN_FIELDS, COLD_SIGNATURE_FIELDS, FINALITY_CERTIFICATE_V2_FIELDS, FOREIGN_BURN_PROOF_FIELDS, FOREIGN_RECORD_FIELDS, LEGACY_CHECKPOINT_FIELDS, MANIFEST_BOOTSTRAP_FIELDS, MANIFEST_CHAIN_BLOCK_FIELDS, MANIFEST_CHAIN_PROOF_FIELDS, MANIFEST_CHAIN_SECTION_FIELDS, OPLOG_ENTRY_FIELDS, SET_TRANSITION_FIELDS, STATE_CHECKPOINT_FIELDS, SURVIVOR_SIGNATURE_FIELDS, TRANSITION_DESCRIPTOR_FIELDS, VALIDATOR_MANIFEST_ENTRY_FIELDS, VALIDATOR_MANIFEST_FIELDS, VOTE_FIELDS, } from "./schema.js";
import { verifyCertificate, } from "./validators.js";
import { finalityPolicyHash, transitionPolicyHash, canonicalManifestHash, bootstrapHash, popMessageBytes, finalityMessageV2Bytes, operationalManifest, survivorIds, transitionTupleBytes, setTransitionHash, manifestChainBlockHash, MANIFEST_CHAIN_PROOF_FORMAT, VALIDATOR_MANIFEST_HASH_MISMATCH as MANIFEST_CHAIN_MISMATCH, networkPolicy, } from "./manifest-chain.js";
const EXPECTED_FORMAT = "MT-BRICK-PROOF-1";
const EXPECTED_CHAIN_ID = "million-tower-testnet-1";
const BLOCK_HASH_DOMAIN = "MT-BLOCK-1";
const OWNERSHIP_DOMAIN = "MT-OWNERSHIP-1";
const CHECKPOINT_DOMAIN = "MT-CHECKPOINT-1";
const CHECKPOINT_BLOCKS_DOMAIN = "MT-CKPT-BLOCKS-1";
const CHECKPOINT_STATE_DOMAIN = "MT-CHECKPOINT-STATE-1";
const CHECKPOINT_STATE_FORMAT = "MT-STATE-CHECKPOINT-1";
const CHECKPOINT_STATE_VERSION = "MT-CHECKPOINT-1";
/** Raíz Merkle binaria MT-DUAL-1024 (duplicando el último elemento si es impar). */
function merkleRoot1024(hashes, domain) {
    if (hashes.length === 0)
        return ZERO_HASH_1024;
    let level = [...hashes];
    while (level.length > 1) {
        const next = [];
        for (let i = 0; i < level.length; i += 2) {
            const a = level[i];
            const b = (level[i + 1] ?? a);
            next.push(mtDual1024(a + b, domain));
        }
        level = next;
    }
    return level[0];
}
function isObj(v) {
    return typeof v === "object" && v !== null && !Array.isArray(v);
}
/** Núcleo firmado de un bloque, reimplementado aquí (no se importa la cadena). */
function blockCoreBytes(block) {
    const core = {
        block_number: block.block_number,
        brick_number: block.brick_number,
        payload: block.payload,
        prev_hash: block.prev_hash,
    };
    if (block.oplog_anchor)
        core.oplog_anchor = block.oplog_anchor;
    return canonicalBytes(core);
}
function blockTransition(block, chainId) {
    return {
        chain_id: chainId,
        kind: block.block_number === 0 ? "GENESIS" : "MINT_BRICK",
        sequence: block.block_number,
        prev_state: block.prev_hash,
        transition_hash: block.block_hash,
    };
}
class Components {
    list = [];
    set(name, status, detail) {
        const existing = this.list.find((c) => c.name === name);
        if (existing) {
            // Un FAIL ya registrado no se degrada; un OK se sustituye por el fallo posterior.
            if (existing.status === "FAIL" && status === "OK")
                return;
            existing.status = status;
            if (detail)
                existing.detail = existing.detail ? `${existing.detail}; ${detail}` : detail;
            return;
        }
        this.list.push({ name, status, ...(detail ? { detail } : {}) });
    }
    get all() {
        return this.list;
    }
    hasFail() {
        return this.list.some((c) => c.status === "FAIL");
    }
    hasMissing() {
        return this.list.some((c) => c.status === "MISSING");
    }
}
/**
 * Base64 CANÓNICO (presentación estricta): la cadena debe ser exactamente
 * la codificación canónica de sus bytes. El decodificador de Node ignora
 * caracteres fuera del alfabeto y tolera el relleno corrupto o ausente,
 * así que sin este control dos presentaciones byte-distintas del mismo
 * material (PoP, firmas) producen el mismo veredicto (hallazgo FC-02 de
 * la capa adversarial). La casa ya exige esta canonicalidad para las
 * claves (decodeStrictBase64 en src/keys.ts); este juicio la extiende al
 * material de firma que el verificador decodifica.
 */
function isCanonicalBase64(value) {
    return typeof value === "string" && Buffer.from(value, "base64").toString("base64") === value;
}
/**
 * Juicio de un certificado de finalidad v1 con la presentación estricta
 * de FC-02 por delante: un voto cuya firma no es base64 canónico se
 * rechaza con su motivo fino, sin llegar al decodificador tolerante. El
 * resto del juicio es verifyCertificate, compartido con las demás rutas.
 */
function judgeV1Certificate(manifest, certRaw) {
    if (isObj(certRaw) && Array.isArray(certRaw.votes)) {
        const bad = [];
        for (const voteRaw of certRaw.votes) {
            if (isObj(voteRaw) && typeof voteRaw.signature === "string" && !isCanonicalBase64(voteRaw.signature)) {
                bad.push(`El voto de ${typeof voteRaw.validator_id === "string" ? voteRaw.validator_id : "?"} del certificado v1 no es base64 canónico: la presentación estricta rechaza relleno o caracteres fuera del alfabeto`);
            }
        }
        if (bad.length > 0)
            return { valid: false, distinct_signers: 0, errors: bad };
    }
    return verifyCertificate(manifest, certRaw);
}
function judgeManifestChain(sectionRaw, ctx) {
    const errors = [];
    const err = (m) => {
        errors.push(m);
    };
    const manifests = [];
    const hashes = [];
    const finish = (bootstrap) => ({
        errors,
        ...(bootstrap ? { bootstrap } : {}),
        manifests,
        hashes,
        ...(errors.length === 0 && manifests.length
            ? {
                current: manifests[manifests.length - 1],
                currentHash: hashes[hashes.length - 1],
            }
            : {}),
        manifestAtHeight(h) {
            let found;
            for (const m of manifests)
                if (h >= m.effective_height)
                    found = m;
            return found;
        },
    });
    if (!isObj(sectionRaw)) {
        err("La sección de cadena de manifiestos no es un objeto");
        return finish();
    }
    const section = sectionRaw;
    const secExtra = firstUnknownField(sectionRaw, MANIFEST_CHAIN_SECTION_FIELDS);
    if (secExtra !== null)
        err(schemaFieldNotAllowedMessage("la sección de cadena de manifiestos", secExtra));
    if (!Array.isArray(section.manifests) || section.manifests.length === 0) {
        err("La cadena de manifiestos no trae ningún manifiesto");
        return finish();
    }
    if (!Array.isArray(section.transitions)) {
        err("La cadena de manifiestos no trae la lista de transiciones");
        return finish();
    }
    if (section.transitions.length !== section.manifests.length - 1) {
        err(`La cadena trae ${section.transitions.length} transiciones para ${section.manifests.length} manifiestos (debe haber exactamente una por sucesor)`);
    }
    // --- Bootstrap ---
    const bootstrap = section.bootstrap;
    if (!isObj(bootstrap)) {
        err("La cadena de manifiestos no trae bootstrap");
        return finish();
    }
    const bs = bootstrap;
    const bsExtra = firstUnknownField(bootstrap, MANIFEST_BOOTSTRAP_FIELDS);
    if (bsExtra !== null)
        err(schemaFieldNotAllowedMessage("el bootstrap de la cadena de manifiestos", bsExtra));
    if (bs.format !== "MT-VALIDATOR-MANIFEST-BOOTSTRAP-1")
        err("El bootstrap no es un MT-VALIDATOR-MANIFEST-BOOTSTRAP-1");
    const policy = networkPolicy(bs.network_id);
    if (!policy) {
        err(`El bootstrap declara una red sin política autenticada en este verificador: ${JSON.stringify(bs.network_id)}`);
        return finish(bs);
    }
    if (bs.chain_id !== ctx.chainId || bs.chain_id !== policy.chain_id) {
        err(`El bootstrap es de otra cadena (${JSON.stringify(bs.chain_id)})`);
    }
    if (typeof bs.genesis_hash !== "string" || !/^[0-9a-f]{256}$/.test(bs.genesis_hash)) {
        err("El bootstrap no trae un genesis_hash MT-DUAL-1024");
    }
    else if (ctx.genesisHash !== undefined && bs.genesis_hash !== ctx.genesisHash) {
        err(`${MANIFEST_CHAIN_MISMATCH}: el hash del génesis del bootstrap no coincide con el génesis del paquete`);
    }
    if (!Number.isSafeInteger(bs.bootstrap_epoch) || bs.bootstrap_epoch < 0)
        err("bootstrap_epoch no es una época válida");
    if (!Number.isSafeInteger(bs.bootstrap_height) || bs.bootstrap_height < 0)
        err("bootstrap_height no es una altura válida");
    if (!Number.isSafeInteger(bs.finality_activation_height) || bs.finality_activation_height < 0)
        err("finality_activation_height no es una altura válida");
    if (typeof bs.initial_manifest_hash !== "string" || !/^[0-9a-f]{256}$/.test(bs.initial_manifest_hash))
        err("El bootstrap no trae un initial_manifest_hash MT-DUAL-1024");
    // La autoridad fría está asentada si y solo si el bootstrap la publica
    // (cold_authority !== null); la política de transición comprometida
    // en la raíz depende de ese hecho y se contrasta contra la derivada.
    const coldSeated = bs.cold_authority !== null && bs.cold_authority !== undefined;
    if (bs.finality_policy_hash !== finalityPolicyHash(policy.network_id))
        err("La política de finalidad del bootstrap no es la política autenticada de la red");
    if (bs.transition_policy_hash !== transitionPolicyHash(policy.network_id, coldSeated))
        err("La política de transición del bootstrap no es la política autenticada de la red para su autoridad fría declarada");
    const coldMap = new Map();
    if (coldSeated) {
        if (!isObj(bs.cold_authority)) {
            err("La autoridad fría del bootstrap no es un objeto");
        }
        else {
            const caExtra = firstUnknownField(bs.cold_authority, COLD_AUTHORITY_FIELDS);
            if (caExtra !== null)
                err(schemaFieldNotAllowedMessage("la autoridad fría del bootstrap", caExtra));
            if (bs.cold_authority.threshold !== policy.cold_threshold) {
                err(`El umbral frío del bootstrap (${JSON.stringify(bs.cold_authority.threshold)}) no es el de la política autenticada (${policy.cold_threshold})`);
            }
            const cust = Array.isArray(bs.cold_authority.custodians) ? bs.cold_authority.custodians : [];
            if (!Array.isArray(bs.cold_authority.custodians))
                err("La autoridad fría no trae la lista de custodios");
            if (cust.length !== policy.cold_custodian_count) {
                err(`La autoridad fría debe tener ${policy.cold_custodian_count} custodios (política autenticada); trae ${cust.length}`);
            }
            const cids = new Set();
            const ckeys = new Set();
            cust.forEach((c, i) => {
                if (!isObj(c)) {
                    err(`El custodio frío ${i} del bootstrap no es un objeto`);
                    return;
                }
                const cExtra = firstUnknownField(c, COLD_CUSTODIAN_FIELDS);
                if (cExtra !== null)
                    err(schemaFieldNotAllowedMessage(`el custodio frío ${i} del bootstrap`, cExtra));
                if (typeof c.custodian_id !== "string" || c.custodian_id.length === 0)
                    err(`El custodio frío ${i} no declara custodian_id`);
                else if (cids.has(c.custodian_id))
                    err(`custodian_id duplicado en el bootstrap: ${c.custodian_id}`);
                else
                    cids.add(c.custodian_id);
                if (typeof c.public_key !== "string" || !isSlhDsaShake256sPublicKey(c.public_key))
                    err(`La clave del custodio frío ${i} no es una clave pública SLH-DSA-SHAKE-256s canónica`);
                else if (ckeys.has(c.public_key))
                    err("Dos custodios fríos del bootstrap comparten la misma clave pública");
                else
                    ckeys.add(c.public_key);
                if (typeof c.custodian_id === "string" && typeof c.public_key === "string")
                    coldMap.set(c.custodian_id, c.public_key);
            });
        }
    }
    // --- Manifiestos: forma, huella y posesión ---
    section.manifests.forEach((mRaw, i) => {
        if (!isObj(mRaw)) {
            err(`El manifiesto ${i} de la cadena no es un objeto`);
            hashes[i] = "";
            return;
        }
        const m = mRaw;
        const mExtra = firstUnknownField(mRaw, CANONICAL_MANIFEST_FIELDS);
        if (mExtra !== null)
            err(schemaFieldNotAllowedMessage(`el manifiesto ${i} de la cadena`, mExtra));
        if (m.format !== "MT-VALIDATOR-MANIFEST-1" || m.schema_version !== "1")
            err(`El manifiesto ${i} no es un MT-VALIDATOR-MANIFEST-1 schema_version "1"`);
        if (m.chain_id !== bs.chain_id || m.network_id !== policy.network_id)
            err(`El manifiesto ${i} no pertenece a la cadena/red del bootstrap`);
        if (m.epoch !== bs.bootstrap_epoch + i) {
            err(`El manifiesto ${i} declara epoch=${JSON.stringify(m.epoch)}: las épocas deben ser consecutivas desde la del bootstrap (${bs.bootstrap_epoch}); un salto de época no es admisible`);
        }
        if (!Number.isSafeInteger(m.effective_height) || m.effective_height < 0)
            err(`La altura efectiva del manifiesto ${i} no es válida`);
        else if (i === 0 && m.effective_height !== bs.bootstrap_height)
            err(`El manifiesto inicial entra en vigor en ${m.effective_height} pero el bootstrap declara el corte en ${bs.bootstrap_height}`);
        else if (i > 0 && Number.isSafeInteger(manifests[i - 1]?.effective_height) && m.effective_height <= manifests[i - 1].effective_height) {
            err(`El manifiesto ${i} no entra en vigor estrictamente tras el anterior`);
        }
        if (i === 0) {
            if (m.epoch === 0 && m.prev_manifest_hash !== null)
                err("El manifiesto de la época 0 debe declarar prev_manifest_hash null");
            else if (m.epoch > 0 && (typeof m.prev_manifest_hash !== "string" || !/^[0-9a-f]{256}$/.test(m.prev_manifest_hash))) {
                err("El manifiesto inicial con corte debe declarar la huella (no verificable aquí) de su predecesor anterior al corte");
            }
        }
        else if (hashes[i - 1] && m.prev_manifest_hash !== hashes[i - 1]) {
            err(`${MANIFEST_CHAIN_MISMATCH}: el manifiesto ${i} declara prev_manifest_hash distinto de la huella de su predecesor`);
        }
        if (m.finality_policy_hash !== bs.finality_policy_hash)
            err(`El manifiesto ${i} declara una política de finalidad distinta de la anclada en la raíz (política cambiada desde el manifiesto)`);
        if (m.transition_policy_hash !== bs.transition_policy_hash)
            err(`El manifiesto ${i} declara una política de transición distinta de la anclada en la raíz`);
        const entries = Array.isArray(m.validators) ? m.validators : [];
        if (!Array.isArray(m.validators))
            err(`El manifiesto ${i} no trae la lista de validadores`);
        if (entries.length !== policy.validator_count) {
            err(`El manifiesto ${i} debe tener ${policy.validator_count} validadores (política autenticada de la red); trae ${entries.length}`);
        }
        const ids = new Set();
        const keys = new Set();
        entries.forEach((v, j) => {
            if (!isObj(v)) {
                err(`La entrada ${j} del manifiesto ${i} no es un objeto`);
                return;
            }
            const vExtra = firstUnknownField(v, CANONICAL_MANIFEST_ENTRY_FIELDS);
            if (vExtra !== null)
                err(schemaFieldNotAllowedMessage(`la entrada ${j} del manifiesto ${i}`, vExtra));
            if (typeof v.validator_id !== "string" || v.validator_id.length === 0)
                err(`La entrada ${j} del manifiesto ${i} no declara validator_id`);
            else if (ids.has(v.validator_id))
                err(`validator_id duplicado en el manifiesto ${i}: ${v.validator_id}`);
            else
                ids.add(v.validator_id);
            if (typeof v.public_key !== "string" || !isMlDsa87PublicKey(v.public_key))
                err(`La clave de la entrada ${j} del manifiesto ${i} no es una clave pública ML-DSA-87 canónica`);
            else if (keys.has(v.public_key))
                err(`La misma clave pública sirve a dos validadores en el manifiesto ${i}`);
            else
                keys.add(v.public_key);
            if (v.purpose !== "finality")
                err(`La entrada ${j} del manifiesto ${i} declara un propósito no autorizado: ${JSON.stringify(v.purpose)}`);
        });
        let hash = "";
        try {
            hash = canonicalManifestHash(m);
        }
        catch (e) {
            err(`El manifiesto ${i} no se puede canonicalizar para su huella: ${e instanceof Error ? e.message : String(e)}`);
        }
        hashes[i] = hash;
        manifests.push(m);
        // Posesión: cada entrada firma con su propia clave el mensaje
        // MT-VALIDATOR-POP-1 atado a H(M) — sin ella, cualquiera puede
        // listar en un manifiesto claves de las que no es dueño (G14).
        if (hash) {
            entries.forEach((v) => {
                if (!isObj(v) || typeof v.public_key !== "string" || typeof v.proof_of_possession !== "string") {
                    err(`La entrada de ${JSON.stringify(isObj(v) ? v.validator_id : undefined)} del manifiesto ${i} no trae prueba de posesión`);
                    return;
                }
                if (!isCanonicalBase64(v.proof_of_possession)) {
                    err(`La prueba de posesión de ${v.validator_id} en el manifiesto ${i} no es base64 canónico: la presentación estricta rechaza relleno o caracteres fuera del alfabeto (FC-02)`);
                    return;
                }
                let ok = false;
                try {
                    ok = verifyMlDsa87(v.public_key, popMessageBytes({
                        chain_id: m.chain_id,
                        epoch: m.epoch,
                        manifest_hash: hash,
                        validator_id: v.validator_id,
                        public_key: v.public_key,
                    }), Buffer.from(v.proof_of_possession, "base64"));
                }
                catch {
                    ok = false;
                }
                if (!ok)
                    err(`La prueba de posesión de ${v.validator_id} en el manifiesto ${i} no verifica`);
            });
        }
    });
    if (errors.length > 0)
        return finish(bs);
    // --- Encadenamiento y autorización de transiciones ---
    if (hashes[0] !== bs.initial_manifest_hash) {
        err(`${MANIFEST_CHAIN_MISMATCH}: H(M0) calculado desde el manifiesto inicial del paquete no coincide con el initial_manifest_hash del bootstrap`);
    }
    const seenNonces = new Set();
    const seenTuples = new Set();
    for (let k = 0; k < section.transitions.length; k++) {
        const tRaw = section.transitions[k];
        const oldM = manifests[k];
        const newM = manifests[k + 1];
        if (!isObj(tRaw) || !oldM || !newM) {
            err(`La transición ${k} o sus manifiestos no son objetos`);
            continue;
        }
        const t = tRaw;
        const tExtra = firstUnknownField(tRaw, SET_TRANSITION_FIELDS);
        if (tExtra !== null)
            err(schemaFieldNotAllowedMessage(`la transición ${k} de la cadena`, tExtra));
        if (t.format !== "MT-VALIDATOR-SET-TRANSITION-1" || t.schema_version !== "1")
            err(`La transición ${k} no es una MT-VALIDATOR-SET-TRANSITION-1 schema_version "1"`);
        if (t.chain_id !== bs.chain_id || t.network_id !== policy.network_id)
            err(`La transición ${k} no es de esta cadena/red`);
        if (t.old_epoch !== oldM.epoch || t.new_epoch !== newM.epoch || t.new_epoch !== t.old_epoch + 1) {
            err(`La transición ${k} no enlaza épocas consecutivas (${JSON.stringify(t.old_epoch)} → ${JSON.stringify(t.new_epoch)} frente a ${oldM.epoch} → ${newM.epoch})`);
        }
        if (t.old_manifest_hash !== hashes[k])
            err(`${MANIFEST_CHAIN_MISMATCH}: la transición ${k} no coincide con el manifiesto anterior (old_manifest_hash distinto de su huella)`);
        if (t.new_manifest_hash !== hashes[k + 1])
            err(`${MANIFEST_CHAIN_MISMATCH}: la transición ${k} no coincide con el manifiesto sucesor (new_manifest_hash distinto de su huella)`);
        if (t.effective_height !== newM.effective_height || t.transition_height !== t.effective_height - 1) {
            err(`La transición ${k} declara alturas incoherentes (transition_height=${JSON.stringify(t.transition_height)}, effective_height=${JSON.stringify(t.effective_height)}, en vigor del sucesor=${newM.effective_height}): effective_height debe ser transition_height + 1`);
        }
        if (Number.isSafeInteger(oldM.effective_height) && typeof t.transition_height === "number" && t.transition_height < oldM.effective_height) {
            err(`La transición ${k} se produce antes de que el conjunto saliente entrara en vigor (activación retroactiva)`);
        }
        if (t.transition_policy_hash !== bs.transition_policy_hash)
            err(`La transición ${k} declara una política de transición distinta de la anclada en la raíz`);
        if (typeof t.nonce !== "string" || t.nonce.length === 0)
            err(`La transición ${k} no declara nonce`);
        else if (seenNonces.has(t.nonce))
            err(`La transición ${k} reutiliza el nonce de otra transición (replay de transición)`);
        else
            seenNonces.add(t.nonce);
        // Sustituciones derivadas de ambos manifiestos, nunca declaradas:
        // la declaración de la transición debe coincidir EXACTO con ellas.
        const { survivors, retired, added } = survivorIds(oldM, newM);
        if (JSON.stringify(t.retired_validator_ids ?? null) !== JSON.stringify(retired))
            err(`Los retirados declarados de la transición ${k} no son los derivados de ambos manifiestos`);
        if (JSON.stringify(t.added_validator_ids ?? null) !== JSON.stringify(added))
            err(`Los añadidos declarados de la transición ${k} no son los derivados de ambos manifiestos`);
        if (retired.length === 0)
            err(`La transición ${k} no sustituye a nadie: una transición sin cambios no es una ceremonia E-19 válida`);
        else if (retired.length > policy.max_simultaneous_replacements) {
            err(`La transición ${k} sustituye ${retired.length} validadores a la vez: el tope autenticado es ${policy.max_simultaneous_replacements} (deben quedar al menos el quórum de supervivientes firmando): detención, no transición`);
        }
        let tupleBytes;
        try {
            tupleBytes = transitionTupleBytes(t);
            const tupleKey = tupleBytes.toString("hex");
            if (seenTuples.has(tupleKey))
                err(`La transición ${k} repite el tuplo vinculante de otra transición (replay)`);
            else
                seenTuples.add(tupleKey);
        }
        catch (e) {
            err(`El tuplo de la transición ${k} no se puede canonicalizar: ${e instanceof Error ? e.message : String(e)}`);
        }
        // Autorización 1: quórum de SUPERVIVIENTES del conjunto saliente
        // sobre el tuplo (conteo por validator_id distintos; un retirado
        // que firma no es superviviente y no cuenta — G9).
        const oldKeys = new Map(oldM.validators.map((v) => [v.validator_id, v.public_key]));
        const sigs = Array.isArray(t.survivor_signatures) ? t.survivor_signatures : [];
        if (!Array.isArray(t.survivor_signatures))
            err(`La transición ${k} no trae firmas de supervivientes`);
        const sigIds = sigs.map((s) => (isObj(s) ? s.validator_id : undefined));
        if (!sigIds.every((id, idx) => idx === 0 || (typeof sigIds[idx - 1] === "string" && typeof id === "string" && sigIds[idx - 1] < id))) {
            err(`Las firmas de supervivientes de la transición ${k} no vienen en orden estrictamente ascendente por validator_id (presentación canónica)`);
        }
        const validSurvivors = new Set();
        sigs.forEach((s, j) => {
            if (!isObj(s)) {
                err(`La firma de superviviente ${j} de la transición ${k} no es un objeto`);
                return;
            }
            const sExtra = firstUnknownField(s, SURVIVOR_SIGNATURE_FIELDS);
            if (sExtra !== null)
                err(schemaFieldNotAllowedMessage(`la firma de superviviente ${j} de la transición ${k}`, sExtra));
            if (typeof s.validator_id !== "string" || !survivors.includes(s.validator_id)) {
                err(`La firma ${j} de la transición ${k} no es de un superviviente del conjunto saliente (retirado, rotado o ajeno)`);
                return;
            }
            if (!isCanonicalBase64(s.signature)) {
                err(`La firma del superviviente ${s.validator_id} en la transición ${k} no es base64 canónico: la presentación estricta rechaza relleno o caracteres fuera del alfabeto (FC-02)`);
                return;
            }
            let ok = false;
            try {
                ok = tupleBytes !== undefined && typeof s.signature === "string" && verifyMlDsa87(oldKeys.get(s.validator_id), tupleBytes, Buffer.from(s.signature, "base64"));
            }
            catch {
                ok = false;
            }
            if (!ok)
                err(`La firma del superviviente ${s.validator_id} en la transición ${k} no verifica sobre el tuplo`);
            else
                validSurvivors.add(s.validator_id);
        });
        if (validSurvivors.size < policy.quorum) {
            err(`La transición ${k} reúne ${validSurvivors.size} firmas válidas de supervivientes distintos: el quórum autenticado del conjunto saliente es ${policy.quorum}`);
        }
        // Autorización 2: autoridad fría 2-de-3 sobre el MISMO tuplo —
        // dos firmas SLH-DSA INDEPENDIENTES de custodios distintos del
        // bootstrap; sin autoridad asentada, ninguna transición E-19 es
        // autorizable (declarado en la raíz, no negociable por el paquete).
        const coldSigs = Array.isArray(t.cold_signatures) ? t.cold_signatures : [];
        if (!Array.isArray(t.cold_signatures))
            err(`La transición ${k} no trae firmas frías`);
        if (!coldSeated) {
            err(`La transición ${k} es una ceremonia E-19 pero la raíz no tiene autoridad fría asentada: ninguna transición es autorizable en esta red`);
        }
        else {
            const coldIds = coldSigs.map((s) => (isObj(s) ? s.custodian_id : undefined));
            if (!coldIds.every((id, idx) => idx === 0 || (typeof coldIds[idx - 1] === "string" && typeof id === "string" && coldIds[idx - 1] < id))) {
                err(`Las firmas frías de la transición ${k} no vienen en orden estrictamente ascendente por custodian_id (presentación canónica)`);
            }
            const validCold = new Set();
            coldSigs.forEach((s, j) => {
                if (!isObj(s)) {
                    err(`La firma fría ${j} de la transición ${k} no es un objeto`);
                    return;
                }
                const sExtra = firstUnknownField(s, COLD_SIGNATURE_FIELDS);
                if (sExtra !== null)
                    err(schemaFieldNotAllowedMessage(`la firma fría ${j} de la transición ${k}`, sExtra));
                if (typeof s.custodian_id !== "string" || !coldMap.has(s.custodian_id)) {
                    err(`La firma fría ${j} de la transición ${k} no es de un custodio de la autoridad fría anclada en la raíz`);
                    return;
                }
                if (!isCanonicalBase64(s.signature)) {
                    err(`La firma fría del custodio ${s.custodian_id} en la transición ${k} no es base64 canónico: la presentación estricta rechaza relleno o caracteres fuera del alfabeto (FC-02)`);
                    return;
                }
                let ok = false;
                try {
                    ok = tupleBytes !== undefined && typeof s.signature === "string" && verifySlhDsaShake256s(coldMap.get(s.custodian_id), tupleBytes, Buffer.from(s.signature, "base64"));
                }
                catch {
                    ok = false;
                }
                if (!ok)
                    err(`La firma fría del custodio ${s.custodian_id} en la transición ${k} no verifica sobre el tuplo`);
                else
                    validCold.add(s.custodian_id);
            });
            if (validCold.size < policy.cold_threshold) {
                err(`La transición ${k} reúne ${validCold.size} firmas frías válidas de custodios distintos: la autoridad fría exige ${policy.cold_threshold}-de-${policy.cold_custodian_count}`);
            }
        }
    }
    return finish(bs);
}
/** ¿Tiene este objeto la forma de un MT-FINALITY-CERTIFICATE-2? */
function isV2CertificateShape(certRaw) {
    return isObj(certRaw) && certRaw.format === "MT-FINALITY-CERTIFICATE-2";
}
/**
 * Juicio propio de un certificado de finalidad v2 contra el manifiesto
 * EN VIGOR en su altura: el certificado compromete la época y H(M) de
 * ese manifiesto y su descriptor debe ser EXACTAMENTE el de la
 * transición esperada; los votos firman el mensaje con dominio
 * MT-FINALITY-V1 (cadena, tipo, secuencia, estado previo, huella de la
 * transición, época, vista 0 y H del manifiesto) y deben alcanzar el
 * quórum de la política autenticada con validator_id distintos del
 * conjunto vigente, en orden estrictamente ascendente.
 */
function judgeV2Certificate(manifest, certRaw, expectedTransition) {
    const errors = [];
    if (!isObj(certRaw))
        return ["El certificado v2 no es un objeto"];
    const cert = certRaw;
    const cExtra = firstUnknownField(certRaw, FINALITY_CERTIFICATE_V2_FIELDS);
    if (cExtra !== null)
        errors.push(schemaFieldNotAllowedMessage("el certificado de finalidad v2", cExtra));
    if (cert.format !== "MT-FINALITY-CERTIFICATE-2")
        errors.push("El certificado no es un MT-FINALITY-CERTIFICATE-2");
    if (!isObj(cert.transition)) {
        errors.push("El certificado v2 no trae el descriptor de transición");
        return errors;
    }
    const tExtra = firstUnknownField(cert.transition, TRANSITION_DESCRIPTOR_FIELDS);
    if (tExtra !== null)
        errors.push(schemaFieldNotAllowedMessage("el descriptor de transición del certificado v2", tExtra));
    try {
        if (canonicalize(cert.transition) !== canonicalize(expectedTransition)) {
            errors.push("El descriptor de transición del certificado v2 no corresponde al bloque esperado");
        }
    }
    catch {
        errors.push("El descriptor de transición del certificado v2 no se puede canonicalizar");
    }
    if (cert.transition.chain_id !== manifest.chain_id)
        errors.push("El certificado v2 es de otra cadena");
    if (cert.epoch !== manifest.epoch) {
        errors.push(`El certificado v2 declara la época ${JSON.stringify(cert.epoch)} pero el manifiesto en vigor en su altura es de la época ${manifest.epoch}`);
    }
    let expectedHash;
    try {
        expectedHash = canonicalManifestHash(manifest);
    }
    catch {
        errors.push("El manifiesto en vigor no se puede canonicalizar para su huella");
    }
    if (expectedHash !== undefined && cert.manifest_hash !== expectedHash) {
        errors.push(`${MANIFEST_CHAIN_MISMATCH}: el certificado v2 compromete un manifiesto (manifest_hash=${typeof cert.manifest_hash === "string" ? cert.manifest_hash.slice(0, 16) : "?"}…) que no es el vigente en su altura (${expectedHash.slice(0, 16)}…)`);
    }
    const policy = networkPolicy(manifest.network_id);
    if (!policy) {
        errors.push(`Red sin política autenticada: ${JSON.stringify(manifest.network_id)}`);
        return errors;
    }
    const keyById = new Map(manifest.validators.map((v) => [v.validator_id, v.public_key]));
    let bytes;
    try {
        bytes = finalityMessageV2Bytes({ transition: cert.transition, epoch: cert.epoch, manifest_hash: cert.manifest_hash });
    }
    catch (e) {
        errors.push(`El mensaje de finalidad v2 no se puede canonicalizar: ${e instanceof Error ? e.message : String(e)}`);
    }
    const votes = Array.isArray(cert.votes) ? cert.votes : [];
    if (!Array.isArray(cert.votes) || votes.length === 0)
        errors.push("El certificado v2 no trae votos");
    const voteIds = votes.map((v) => (isObj(v) ? v.validator_id : undefined));
    if (!voteIds.every((id, idx) => idx === 0 || (typeof voteIds[idx - 1] === "string" && typeof id === "string" && voteIds[idx - 1] < id))) {
        errors.push("Los votos del certificado v2 no vienen en orden estrictamente ascendente por validator_id (presentación canónica)");
    }
    const valid = new Set();
    votes.forEach((voteRaw, j) => {
        if (!isObj(voteRaw)) {
            errors.push(`El voto ${j} del certificado v2 no es un objeto`);
            return;
        }
        const vExtra = firstUnknownField(voteRaw, VOTE_FIELDS);
        if (vExtra !== null)
            errors.push(schemaFieldNotAllowedMessage(`el voto ${j} del certificado v2`, vExtra));
        const vote = voteRaw;
        if (typeof vote.validator_id !== "string" || !keyById.has(vote.validator_id)) {
            errors.push(`El voto ${j} del certificado v2 no es de un validador del manifiesto vigente en su altura`);
            return;
        }
        if (!isCanonicalBase64(vote.signature)) {
            errors.push(`El voto de ${vote.validator_id} en el certificado v2 no es base64 canónico: la presentación estricta rechaza relleno o caracteres fuera del alfabeto (FC-02)`);
            return;
        }
        let ok = false;
        try {
            ok = bytes !== undefined && typeof vote.signature === "string" && verifyMlDsa87(keyById.get(vote.validator_id), bytes, Buffer.from(vote.signature, "base64"));
        }
        catch {
            ok = false;
        }
        if (!ok)
            errors.push(`El voto de ${vote.validator_id} en el certificado v2 no verifica sobre el mensaje MT-FINALITY-V1`);
        else
            valid.add(vote.validator_id);
    });
    if (valid.size < policy.quorum) {
        errors.push(`El certificado v2 reúne ${valid.size} votos válidos de validadores distintos: el quórum autenticado es ${policy.quorum}`);
    }
    return errors;
}
/** El manifiesto plano del paquete ¿es la proyección del vigente encadenado? */
function flatMatchesChained(flat, chained) {
    const projected = operationalManifest(chained);
    if (flat.chain_id !== projected.chain_id || flat.quorum !== projected.quorum)
        return false;
    if (!Array.isArray(flat.validators) || flat.validators.length !== projected.validators.length)
        return false;
    const flatById = new Map(flat.validators.map((v) => [v.validator_id, v.public_key]));
    if (flatById.size !== flat.validators.length)
        return false;
    return projected.validators.every((v) => flatById.get(v.validator_id) === v.public_key);
}
export function verifyBrickProof(pkgInput, anchors) {
    const components = new Components();
    const errors = [];
    const fail = (component, msg) => {
        components.set(component, "FAIL", msg);
        errors.push(`${component}: ${msg}`);
    };
    const missing = (component, msg) => {
        components.set(component, "MISSING", msg);
        errors.push(`${component}: ${msg}`);
    };
    if (!isObj(pkgInput)) {
        components.set("format", "FAIL", "El paquete no es un objeto JSON");
        return { verdict: "NOT_VERIFIABLE", components: components.all, errors: ["El paquete no es un objeto JSON"] };
    }
    const pkg = pkgInput;
    if (pkg.format !== EXPECTED_FORMAT) {
        components.set("format", "FAIL", `Formato no reconocido: ${JSON.stringify(pkg.format)}`);
        return {
            verdict: "NOT_VERIFIABLE",
            components: components.all,
            errors: [`Formato de paquete no reconocido: ${JSON.stringify(pkg.format)}`],
        };
    }
    components.set("format", "OK");
    // --- Esquema cerrado del sobre (F-20-02, remediación C-AUD-20) ---
    // Las rutas de puente y de manifiesto cierran su sobre desde su
    // nacimiento; esta ruta cerraba el manifiesto y sus entradas pero no
    // el paquete mismo: un campo extra viajaba sin rechazo. La lista es
    // la forma exacta que el productor emite (src/proof.ts).
    const pkgExtra = firstUnknownField(pkg, BRICK_PROOF_PACKAGE_FIELDS);
    if (pkgExtra !== null) {
        fail("format", schemaFieldNotAllowedMessage("el paquete MT-BRICK-PROOF-1", pkgExtra));
    }
    // --- Presencia de piezas (sin esto no se puede decidir: INCOMPLETE) ---
    const chainId = pkg.chain_id;
    if (typeof chainId !== "string")
        missing("chain_id", "El paquete no declara chain_id");
    else if (chainId !== EXPECTED_CHAIN_ID)
        fail("chain_id", `Cadena inesperada: ${chainId}`);
    else
        components.set("chain_id", "OK");
    const fingerprint = pkg.constitution_fingerprint;
    if (typeof fingerprint !== "string" || !/^[0-9a-f]{256}$/.test(fingerprint)) {
        missing("constitution_anchor", "El paquete no trae una huella constitucional MT-DUAL-1024");
    }
    const genesis = pkg.genesis;
    if (!isObj(genesis) || !isObj(genesis.payload))
        missing("genesis", "El paquete no trae el bloque génesis");
    const blocks = pkg.blocks;
    if (!Array.isArray(blocks))
        missing("block_linkage", "El paquete no trae la lista de bloques");
    const subject = pkg.subject;
    if (!isObj(subject) || typeof subject.brick_number !== "number") {
        missing("subject_brick", "El paquete no declara el ladrillo sujeto de la prueba");
    }
    const params = pkg.public_parameters;
    const manifest = isObj(params) ? params.validator_manifest : undefined;
    if (!isObj(manifest) || !Array.isArray(manifest.validators)) {
        missing("validator_manifest", "El paquete no trae el manifiesto público de validadores");
    }
    // --- Esquema cerrado del sujeto y de los parámetros públicos
    // (F-20-02, remediación C-AUD-20): los dos objetos de primera clase
    // que quedaban abiertos en esta ruta, con sus piezas anidadas
    // (inscripción y partes del factor de posición). ---
    if (isObj(subject)) {
        const sExtra = firstUnknownField(subject, BRICK_PROOF_SUBJECT_FIELDS);
        if (sExtra !== null) {
            fail("subject_brick", schemaFieldNotAllowedMessage("el sujeto de la prueba MT-BRICK-PROOF-1", sExtra));
        }
        if (isObj(subject.inscription)) {
            const iExtra = firstUnknownField(subject.inscription, BRICK_PROOF_INSCRIPTION_FIELDS);
            if (iExtra !== null) {
                fail("subject_brick", schemaFieldNotAllowedMessage("la inscripción del sujeto de la prueba", iExtra));
            }
        }
        if (isObj(subject.position_factor_parts)) {
            const pExtra = firstUnknownField(subject.position_factor_parts, BRICK_PROOF_POSITION_FACTOR_PARTS_FIELDS);
            if (pExtra !== null) {
                fail("subject_brick", schemaFieldNotAllowedMessage("las partes del factor de posición del sujeto", pExtra));
            }
        }
    }
    if (isObj(params)) {
        const ppExtra = firstUnknownField(params, BRICK_PROOF_PUBLIC_PARAMETERS_FIELDS);
        if (ppExtra !== null) {
            fail("public_parameters", schemaFieldNotAllowedMessage("los parámetros públicos de la prueba MT-BRICK-PROOF-1", ppExtra));
        }
    }
    if (components.hasMissing() || typeof chainId !== "string" || !isObj(genesis) || !Array.isArray(blocks) || !isObj(subject)) {
        // Sin las piezas básicas no se sigue: lo que falte manda INCOMPLETE
        // (salvo que algo ya haya fallado criptográficamente, que manda INVALID).
        return {
            verdict: components.hasFail() ? "INVALID" : "INCOMPLETE",
            components: components.all,
            errors,
            ...(isObj(subject) && typeof subject.brick_number === "number"
                ? { brick_number: subject.brick_number }
                : {}),
        };
    }
    const chain = chainId;
    const allBlocks = [genesis, ...blocks];
    // --- Manifiesto: formato, esquema cerrado, unicidad, cadena y quórum ---
    // Espejo de la ruta de puente (SCH-BRG-11/12, paso A5) sobre el MISMO
    // objeto: la raíz de confianza no puede ser el único objeto de primera
    // clase sin formato ni esquema cerrado en su ruta (F-A6-02), y los
    // validator_id deben ser únicos (F-A6-03: las entradas se consumen por
    // primera coincidencia). Todo rechazo es FAIL con veredicto INVALID,
    // nunca una excepción del verificador. Lo que el manifiesto NO tiene
    // todavía es anclaje externo: es autodeclarado dentro del paquete y se
    // comprueba en forma y en firmas internas, no contra un valor anclado
    // (F-A6-01, declarado en la cabecera de este fichero).
    if (manifest) {
        const m = manifest;
        if (m.format !== "MT-VALIDATOR-MANIFEST-1") {
            fail("validator_manifest", `El manifiesto no es un MT-VALIDATOR-MANIFEST-1 (format=${JSON.stringify(m.format)})`);
        }
        const mExtra = firstUnknownField(m, VALIDATOR_MANIFEST_FIELDS);
        if (mExtra !== null) {
            fail("validator_manifest", schemaFieldNotAllowedMessage("el manifiesto de validadores del paquete", mExtra));
        }
        m.validators.forEach((ve, i) => {
            if (!isObj(ve)) {
                fail("validator_manifest", `La entrada de validador ${i} del manifiesto no es un objeto`);
                return;
            }
            const veExtra = firstUnknownField(ve, VALIDATOR_MANIFEST_ENTRY_FIELDS);
            if (veExtra !== null) {
                fail("validator_manifest", schemaFieldNotAllowedMessage(`la entrada de validador ${i} del manifiesto`, veExtra));
            }
        });
        const seenIds = new Set();
        for (const ve of m.validators) {
            if (isObj(ve) && typeof ve.validator_id === "string") {
                if (seenIds.has(ve.validator_id)) {
                    fail("validator_manifest", `validator_id duplicado en el manifiesto: ${ve.validator_id}`);
                }
                seenIds.add(ve.validator_id);
            }
        }
        if (m.chain_id !== chain) {
            fail("validator_manifest", "El manifiesto es de otra cadena");
        }
        else if (m.quorum !== 3 || m.validators.length !== 4) {
            fail("validator_manifest", `El manifiesto no declara 4 validadores con quórum 3 (quórum=${m.quorum}, n=${m.validators.length})`);
        }
        if (!components.all.some((c) => c.name === "validator_manifest" && c.status === "FAIL")) {
            components.set("validator_manifest", "OK");
        }
    }
    // --- Cadena de manifiestos (MT-VALIDATOR-MANIFEST-CHAIN-1, cierre
    // F-A6-01): si el paquete la trae, se juzga entera y el manifiesto
    // plano debe ser la proyección del manifiesto VIGENTE de la cadena.
    // Sin sección, el paquete es del formato previo al cierre y la
    // atribución queda declarada no establecida (nunca anclada en
    // silencio). El juicio vive en judgeManifestChain (lógica propia).
    const sectionRaw = isObj(params) ? params.manifest_chain : undefined;
    let chainJudgment;
    let flatCrossFailed = false;
    if (sectionRaw !== undefined && sectionRaw !== null) {
        chainJudgment = judgeManifestChain(sectionRaw, {
            chainId: chain,
            genesisHash: genesis.block_hash,
        });
        if (chainJudgment.errors.length > 0) {
            fail("validator_manifest_chain", chainJudgment.errors.join("; "));
        }
        else {
            components.set("validator_manifest_chain", "OK", "Cadena de manifiestos íntegra: bootstrap coherente, encadenamiento sin huecos, posesión y autorización de cada transición verificadas");
            if (manifest && chainJudgment.current && !flatMatchesChained(manifest, chainJudgment.current)) {
                flatCrossFailed = true;
                fail("validator_manifest", `${MANIFEST_CHAIN_MISMATCH}: el manifiesto presentado no coincide con el manifiesto vigente de la cadena de manifiestos del paquete (H del vigente: ${chainJudgment.currentHash})`);
            }
        }
    }
    else {
        components.set("validator_manifest_chain", "SKIPPED", "El paquete no trae cadena de manifiestos (formato previo a MT-VALIDATOR-MANIFEST-CHAIN-1): su manifiesto es autodeclarado y la atribución de finalidad NO está anclada");
    }
    // --- Génesis: forma, ancla constitucional y suministro 0 ---
    const gp = genesis.payload;
    if (genesis.block_number !== 0 ||
        genesis.brick_number !== null ||
        genesis.prev_hash !== ZERO_HASH_1024 ||
        gp.schema !== "MT-GENESIS-1" ||
        gp.chain_id !== chain ||
        gp.network !== "testnet" ||
        gp.supply !== 0) {
        fail("genesis", "El bloque génesis no tiene la forma esperada (bloque 0, testnet, suministro 0)");
    }
    else {
        components.set("genesis", "OK");
    }
    if (typeof fingerprint === "string" && /^[0-9a-f]{256}$/.test(fingerprint)) {
        if (gp.constitution_fingerprint !== fingerprint) {
            fail("constitution_anchor", "La huella constitucional del paquete no coincide con la anclada en el génesis");
        }
        else {
            components.set("constitution_anchor", "OK");
        }
    }
    // --- Ancla externa (auditoría fase 14, hallazgo AUD-01, extendida por
    // el cierre de F-A6-01) ---
    // Todo lo verificado sin anclas prueba CONSISTENCIA INTERNA del paquete:
    // un paquete forjado autoconsistente (génesis y validadores del atacante
    // con la huella constitucional pública copiada) resultaba VALID sin
    // ninguna señal de alarma. Con anclas publicadas fuera del paquete se
    // detecta aquí la falsificación que toque la huella constitucional o el
    // hash del génesis. Desde MT-VALIDATOR-MANIFEST-CHAIN-1, el ancla del
    // manifiesto inicial cubre además la RAÍZ de la cadena de manifiestos:
    // es el contraste que convierte la sustitución del manifiesto (el caso
    // G2 de la revisión A6) en INVALID con motivo
    // VALIDATOR_MANIFEST_HASH_MISMATCH. El ancla del manifiesto actual es
    // solo acelerador: discrepancia invalida, ausencia no.
    let initialAnchorMatched = false;
    // F-ADV-02: un ancla DE MANIFIESTO (inicial o actual) aportada por el
    // llamante y contradicha por el juicio degrada la atribución a INVALID;
    // las anclas de constitución/génesis no tienen ese efecto (XG-03/XA-07).
    // El ancla del bootstrap (F-20-01) es un ancla de manifiesto a este
    // efecto: compromete el bootstrap entero, activación incluida.
    let manifestAnchorFailed = false;
    const anyAnchor = anchors &&
        (anchors.constitution_fingerprint !== undefined ||
            anchors.genesis_block_hash !== undefined ||
            anchors.initial_validator_manifest_hash !== undefined ||
            anchors.current_validator_manifest_hash !== undefined ||
            anchors.bootstrap_hash !== undefined);
    if (anyAnchor) {
        let anchorFailed = false;
        if (anchors.constitution_fingerprint !== undefined && anchors.constitution_fingerprint !== fingerprint) {
            fail("external_anchor", "La huella constitucional del paquete NO coincide con la ancla externa esperada");
            anchorFailed = true;
        }
        if (anchors.genesis_block_hash !== undefined && anchors.genesis_block_hash !== genesis.block_hash) {
            fail("external_anchor", "El hash del bloque génesis del paquete NO coincide con el ancla externa esperada");
            anchorFailed = true;
        }
        if (anchors.initial_validator_manifest_hash !== undefined) {
            if (!chainJudgment) {
                fail("validator_manifest_anchor", `${MANIFEST_CHAIN_MISMATCH}: se aportó el ancla externa del manifiesto inicial pero el paquete no trae cadena de manifiestos que contrastar`);
                anchorFailed = true;
                manifestAnchorFailed = true;
            }
            else if (!chainJudgment.bootstrap || anchors.initial_validator_manifest_hash !== chainJudgment.bootstrap.initial_manifest_hash) {
                fail("validator_manifest_anchor", `${MANIFEST_CHAIN_MISMATCH}: el bootstrap de la cadena presentada no es el bootstrap publicado (su initial_manifest_hash no coincide con el ancla externa)`);
                anchorFailed = true;
                manifestAnchorFailed = true;
            }
            else if (chainJudgment.hashes[0] !== anchors.initial_validator_manifest_hash) {
                fail("validator_manifest_anchor", `${MANIFEST_CHAIN_MISMATCH}: H(M0) calculado desde el manifiesto inicial del paquete no coincide con el ancla externa publicada`);
                anchorFailed = true;
                manifestAnchorFailed = true;
            }
            else {
                components.set("validator_manifest_anchor", "OK", "Contraste exacto de este componente: el initial_manifest_hash declarado en el bootstrap presentado coincide con el ancla externa aportada, y H(M0), calculado desde el manifiesto inicial del paquete, coincide con ambos. Este componente no contrasta nada más del bootstrap: su genesis_hash y el resto de su contenido los juzgan los componentes genesis, validator_manifest_chain y external_anchor");
                initialAnchorMatched = true;
            }
        }
        if (anchors.current_validator_manifest_hash !== undefined) {
            if (!chainJudgment || !chainJudgment.currentHash) {
                fail("current_manifest_anchor", `${MANIFEST_CHAIN_MISMATCH}: se aportó el ancla del manifiesto actual pero el paquete no trae una cadena de manifiestos válida`);
                anchorFailed = true;
                manifestAnchorFailed = true;
            }
            else if (chainJudgment.currentHash !== anchors.current_validator_manifest_hash) {
                fail("current_manifest_anchor", `${MANIFEST_CHAIN_MISMATCH}: H del manifiesto vigente no coincide con el ancla actual aportada`);
                anchorFailed = true;
                manifestAnchorFailed = true;
            }
            else {
                components.set("current_manifest_anchor", "OK", "El manifiesto vigente coincide con el ancla actual aportada");
            }
        }
        if (anchors.bootstrap_hash !== undefined) {
            // F-20-01/F-20-05: el ancla del bootstrap compromete el bootstrap
            // ENTERO — también finality_activation_height, que H(M0) no
            // cubre — contra H(bootstrap) calculado del presentado.
            if (!chainJudgment || !chainJudgment.bootstrap) {
                fail("bootstrap_anchor", `${MANIFEST_CHAIN_MISMATCH}: se aportó el ancla externa del bootstrap pero el paquete no trae una cadena de manifiestos con bootstrap que contrastar`);
                anchorFailed = true;
                manifestAnchorFailed = true;
            }
            else if (bootstrapHash(chainJudgment.bootstrap) !== anchors.bootstrap_hash) {
                fail("bootstrap_anchor", `${MANIFEST_CHAIN_MISMATCH}: el bootstrap presentado no es el bootstrap publicado: H(bootstrap) no coincide con el ancla externa aportada. El hash del bootstrap compromete su contenido entero —también finality_activation_height, que H(M0) no cubre— (F-20-01)`);
                anchorFailed = true;
                manifestAnchorFailed = true;
            }
            else {
                components.set("bootstrap_anchor", "OK", "H(bootstrap) calculado desde el bootstrap presentado coincide con el ancla externa aportada: el contenido entero del bootstrap —incluida finality_activation_height— es el publicado");
            }
        }
        if (anchorFailed) {
            fail("external_anchor", "Al menos una de las anclas externas aportadas NO coincide con el paquete (ver el componente específico)");
        }
        else {
            components.set("external_anchor", "OK", "El paquete coincide con todas las anclas externas aportadas (huella constitucional, hash del génesis y/o anclas de manifiesto)");
        }
    }
    else {
        components.set("external_anchor", "SKIPPED", "SIN ANCLA EXTERNA: este veredicto prueba la consistencia INTERNA del paquete, no su autenticidad contra la cadena real; un paquete forjado autoconsistente también es internamente válido (AUD-01). Aportar constitution_fingerprint, genesis_block_hash, initial_validator_manifest_hash y bootstrap_hash publicados fuera del paquete permite contrastar la constitución, el génesis, la raíz de la cadena de manifiestos y el bootstrap entero del paquete contra lo publicado.");
    }
    if (chainJudgment && anchors?.initial_validator_manifest_hash === undefined) {
        components.set("validator_manifest_anchor", "SKIPPED", "La cadena de manifiestos es íntegra por dentro, pero su raíz H(M0) no se contrastó contra ningún valor externo: aporta initial_validator_manifest_hash del bootstrap publicado para anclar la atribución");
    }
    if (chainJudgment && anchors?.bootstrap_hash === undefined) {
        components.set("bootstrap_anchor", "SKIPPED", "La cadena de manifiestos es íntegra por dentro, pero el hash del bootstrap H(bootstrap) no se contrastó contra ningún valor externo: sin esa ancla, finality_activation_height y el resto del contenido del bootstrap quedan acreditados solo por la consistencia interna (F-20-01). Aporta bootstrap_hash del bootstrap publicado para anclarlos");
    }
    const validatorPublicKey = typeof gp.validator_public_key === "string" ? gp.validator_public_key : undefined;
    if (!validatorPublicKey)
        missing("validator_signatures", "El génesis no declara la clave del validador firmante");
    // --- Bloques: secuencia, encadenamiento, huellas, firmas y finalidad ---
    let expectedBrick = 1;
    let height = 0;
    let target;
    const subjectBrick = subject.brick_number;
    for (let i = 0; i < allBlocks.length; i++) {
        const block = allBlocks[i];
        if (block.block_number !== i) {
            fail("block_linkage", `El bloque en posición ${i} declara block_number=${block.block_number}`);
        }
        if (i > 0 && block.prev_hash !== allBlocks[i - 1].block_hash) {
            fail("block_linkage", `El bloque ${i} no encadena con el anterior (prev_hash distinto)`);
        }
        let recomputed;
        try {
            recomputed = mtDual1024(blockCoreBytes(block), BLOCK_HASH_DOMAIN);
        }
        catch (e) {
            fail("block_fingerprints", `El bloque ${i} no se puede canonicalizar: ${e instanceof Error ? e.message : String(e)}`);
        }
        if (recomputed !== undefined && recomputed !== block.block_hash) {
            fail("block_fingerprints", `La huella MT-DUAL-1024 del bloque ${i} no coincide (contenido alterado)`);
        }
        if (validatorPublicKey) {
            let sigOk = false;
            try {
                sigOk = verifyMlDsa87(validatorPublicKey, blockCoreBytes(block), Buffer.from(block.validator_signature ?? "", "base64"));
            }
            catch {
                sigOk = false;
            }
            if (!sigOk)
                fail("validator_signatures", `La firma ML-DSA-87 del bloque ${i} no verifica`);
        }
        if (manifest) {
            if (!block.finality) {
                fail("finality_certificates", `El bloque ${i} no trae certificado de finalidad`);
            }
            else {
                const expected = blockTransition(block, chain);
                const certRaw = block.finality;
                if (isV2CertificateShape(certRaw)) {
                    // Certificado v2: solo tiene sentido atado a la cadena de
                    // manifiestos — su mensaje compromete H del vigente en su
                    // altura, y contra ese manifiesto se juzga (juicio propio).
                    if (!chainJudgment || chainJudgment.errors.length > 0) {
                        fail("finality_certificates", `El bloque ${i} trae un certificado MT-FINALITY-CERTIFICATE-2 pero el paquete no trae una cadena de manifiestos válida que lo vincule`);
                    }
                    else {
                        const inForce = chainJudgment.manifestAtHeight(block.block_number);
                        if (!inForce) {
                            fail("finality_certificates", `El bloque ${i} no tiene manifiesto en vigor en la cadena presentada (altura previa al bootstrap)`);
                        }
                        else {
                            const vErrs = judgeV2Certificate(inForce, certRaw, expected);
                            if (vErrs.length > 0) {
                                fail("finality_certificates", `El certificado v2 del bloque ${i} no verifica: ${vErrs.join("; ")}`);
                            }
                        }
                    }
                }
                else {
                    if (canonicalize(block.finality.transition) !== canonicalize(expected)) {
                        fail("finality_certificates", `El certificado del bloque ${i} no corresponde a su transición`);
                    }
                    // Con cadena válida: el certificado v1 se juzga contra el
                    // manifiesto EN VIGOR en la altura del bloque (no contra el
                    // plano del paquete), y tras la altura de activación v2 un
                    // certificado v1 ya no es admisible (G15).
                    const okJudgment = chainJudgment !== undefined && chainJudgment.errors.length === 0 ? chainJudgment : undefined;
                    const activation = okJudgment?.bootstrap?.finality_activation_height;
                    if (activation !== undefined && block.block_number >= activation) {
                        fail("finality_certificates", `El bloque ${i} trae un certificado de finalidad v1 en la altura ${block.block_number}, tras la activación v2 (${activation}): se exige MT-FINALITY-CERTIFICATE-2`);
                    }
                    const inForce = okJudgment?.manifestAtHeight(block.block_number);
                    const effectiveManifest = inForce ? operationalManifest(inForce) : manifest;
                    const vc = judgeV1Certificate(effectiveManifest, block.finality);
                    if (!vc.valid) {
                        fail("finality_certificates", `El certificado del bloque ${i} no alcanza o no verifica: ${vc.errors.join("; ")}`);
                    }
                }
            }
        }
        if (block.brick_number !== null && block.brick_number !== undefined) {
            if (block.brick_number !== expectedBrick) {
                fail("block_linkage", `Ladrillo ${block.brick_number} fuera de secuencia (se esperaba ${expectedBrick})`);
            }
            expectedBrick++;
            height++;
            if (block.brick_number === subjectBrick)
                target = block;
        }
    }
    if (!components.all.some((c) => c.name === "block_linkage" && c.status === "FAIL")) {
        components.set("block_linkage", "OK");
    }
    if (!components.all.some((c) => c.name === "block_fingerprints" && c.status === "FAIL")) {
        components.set("block_fingerprints", "OK");
    }
    if (validatorPublicKey && !components.all.some((c) => c.name === "validator_signatures" && c.status === "FAIL")) {
        components.set("validator_signatures", "OK");
    }
    if (manifest && !components.all.some((c) => c.name === "finality_certificates" && c.status === "FAIL")) {
        components.set("finality_certificates", "OK");
    }
    // --- Altura declarada contra la recalculada ---
    if (typeof pkg.height === "number" && pkg.height !== height) {
        fail("position_factor", `La altura declarada (${pkg.height}) no coincide con la recalculada desde los bloques (${height})`);
    }
    // --- Sujeto: el ladrillo, su inscripción/compromiso y su propiedad ---
    if (!target) {
        missing("subject_brick", `El bloque del ladrillo ${subjectBrick} no viene en el paquete`);
    }
    else {
        const p = target.payload;
        const subj = subject;
        if (p.schema !== "MT-BRICK-V2" || p.brick_number !== subjectBrick || p.asset !== "TOWR") {
            fail("subject_brick", "El payload del bloque del sujeto no es un MT-BRICK-V2 coherente");
        }
        else if (subj.privacy !== p.privacy) {
            fail("subject_brick", "El modo de privacidad declarado no coincide con el del bloque");
        }
        else if (p.privacy === "PUBLIC") {
            const insc = subj.inscription;
            if (!insc || insc.name !== p.name || insc.country !== p.country) {
                fail("subject_brick", "La inscripción pública declarada no coincide con la del bloque");
            }
            else {
                components.set("subject_brick", "OK");
            }
        }
        else {
            const env = p.envelope;
            if (!env || subj.identity_commitment !== env.identity_commitment) {
                fail("subject_brick", "El compromiso de identidad declarado no coincide con el sobre del bloque");
            }
            else {
                components.set("subject_brick", "OK");
            }
        }
        // Compromiso de propiedad: ata el número del ladrillo a su bloque final.
        const expectedOwnership = mtDual1024(canonicalBytes({ block_hash: target.block_hash, brick_number: subjectBrick }), OWNERSHIP_DOMAIN);
        if (subject.ownership_commitment !== expectedOwnership) {
            fail("ownership_commitment", "El compromiso de propiedad no coincide con el recalculado desde el bloque");
        }
        else {
            components.set("ownership_commitment", "OK");
        }
        // Factor de posición M(b,H) = (2H − b)/H recalculado desde el paquete.
        const parts = subject.position_factor_parts;
        const expectedNum = 2 * height - subjectBrick;
        if (!parts || parts.numerator !== expectedNum || parts.denominator !== height) {
            fail("position_factor", `La fracción de posición declarada no es (2H−b)/H con H=${height}: ${JSON.stringify(parts)}`);
        }
        else {
            const declared = subject.position_factor;
            if (typeof declared !== "number" || Math.abs(declared - expectedNum / height) > 1e-12) {
                fail("position_factor", "El factor de posición numérico no coincide con su fracción exacta");
            }
            else if (!components.all.some((c) => c.name === "position_factor" && c.status === "FAIL")) {
                components.set("position_factor", "OK");
            }
        }
    }
    // --- Checkpoint SLH-DSA (opcional): solo si el paquete lo trae ---
    const checkpoint = pkg.checkpoint;
    if (checkpoint === undefined || checkpoint === null) {
        components.set("checkpoint_slh_dsa", "SKIPPED", "El paquete no trae checkpoint");
    }
    else if (typeof checkpoint.state_root === "string") {
        // Vía D-12 (fase 12): checkpoint de estado MT-STATE-CHECKPOINT-1.
        const ckptKey = checkpoint.checkpoint_public_key;
        // Esquema cerrado (R5.2, espejo de checkpoints.ts): el núcleo firmado
        // se reconstruye solo con los campos conocidos, así que un campo extra
        // en el checkpoint del paquete pasaría inadvertido sin este control.
        // La lista de campos viene de la fuente única (src/schema.ts) para
        // que la cadena y este verificador no puedan divergir en la doctrina.
        const ckUnknown = firstUnknownField(checkpoint, STATE_CHECKPOINT_FIELDS);
        if (ckUnknown !== null) {
            fail("checkpoint_slh_dsa", schemaFieldNotAllowedMessage("el checkpoint MT-STATE-CHECKPOINT-1 del paquete", ckUnknown));
        }
        else if (typeof ckptKey !== "string" || ckptKey.length === 0 || typeof checkpoint.signature !== "string") {
            missing("checkpoint_slh_dsa", "El checkpoint de estado no trae su clave pública o su firma");
        }
        else if (checkpoint.format !== CHECKPOINT_STATE_FORMAT ||
            checkpoint.version !== CHECKPOINT_STATE_VERSION ||
            checkpoint.chain_id !== chain) {
            fail("checkpoint_slh_dsa", "El checkpoint de estado no es un MT-STATE-CHECKPOINT-1 de esta cadena");
        }
        else if (typeof checkpoint.latest_brick !== "number" ||
            !Number.isSafeInteger(checkpoint.latest_brick) ||
            checkpoint.latest_brick < 0 ||
            typeof checkpoint.latest_op_seq !== "number" ||
            typeof checkpoint.oplog_merkle_root !== "string" ||
            typeof checkpoint.block_root !== "string" ||
            typeof checkpoint.epoch !== "number" ||
            typeof checkpoint.timestamp_ms !== "number" ||
            typeof checkpoint.ecola_root !== "string" ||
            typeof checkpoint.ecola_count !== "number" ||
            typeof checkpoint.ecola_last_seq !== "number") {
            fail("checkpoint_slh_dsa", "El checkpoint de estado tiene campos malformados");
        }
        else if (checkpoint.latest_brick > height) {
            fail("checkpoint_slh_dsa", `El checkpoint declara latest_brick=${checkpoint.latest_brick}, más allá de los bloques del paquete (H=${height})`);
        }
        else {
            const upto = allBlocks.slice(0, checkpoint.latest_brick + 1).map((b) => b.block_hash);
            const recomputedBlockRoot = merkleRoot1024(upto, CHECKPOINT_BLOCKS_DOMAIN);
            if (recomputedBlockRoot !== checkpoint.block_root) {
                fail("checkpoint_slh_dsa", "La raíz de bloques del checkpoint no coincide con la recalculada desde el paquete");
            }
            else {
                const expectedStateRoot = mtDual1024(canonicalBytes({
                    block_root: checkpoint.block_root,
                    chain_id: chain,
                    height: checkpoint.latest_brick,
                    last_op_seq: checkpoint.latest_op_seq,
                    oplog_merkle_root: checkpoint.oplog_merkle_root,
                }), CHECKPOINT_STATE_DOMAIN);
                if (expectedStateRoot !== checkpoint.state_root) {
                    fail("checkpoint_slh_dsa", "La raíz de estado no es la función pública de sus componentes declarados");
                }
                else {
                    const coreBytes = canonicalBytes({
                        block_root: checkpoint.block_root,
                        chain_id: checkpoint.chain_id,
                        checkpoint_public_key: ckptKey,
                        ecola_count: checkpoint.ecola_count,
                        ecola_last_seq: checkpoint.ecola_last_seq,
                        ecola_root: checkpoint.ecola_root,
                        epoch: checkpoint.epoch,
                        format: checkpoint.format,
                        latest_brick: checkpoint.latest_brick,
                        latest_op_seq: checkpoint.latest_op_seq,
                        oplog_merkle_root: checkpoint.oplog_merkle_root,
                        state_root: checkpoint.state_root,
                        timestamp_ms: checkpoint.timestamp_ms,
                        version: checkpoint.version,
                    });
                    if (!verifySlhDsaShake256s(ckptKey, coreBytes, Buffer.from(checkpoint.signature, "base64"))) {
                        fail("checkpoint_slh_dsa", "La firma SLH-DSA-SHAKE-256s del checkpoint de estado no verifica");
                    }
                    else {
                        components.set("checkpoint_slh_dsa", "OK", "Checkpoint D-12 verificado: raíz de bloques recalculada, raíz de estado y firma SLH-DSA válidas");
                    }
                }
            }
        }
    }
    else {
        const ckptKey = isObj(params) ? params.checkpoint_public_key : undefined;
        // Esquema cerrado (R5.2): la forma legada es exactamente
        // {root, block_count, signature}; cualquier otro campo se rechaza.
        const legacyUnknown = firstUnknownField(checkpoint, LEGACY_CHECKPOINT_FIELDS);
        if (legacyUnknown !== null) {
            fail("checkpoint_slh_dsa", schemaFieldNotAllowedMessage("el checkpoint legado del paquete", legacyUnknown));
        }
        else if (!ckptKey || typeof checkpoint.root !== "string" || typeof checkpoint.signature !== "string") {
            missing("checkpoint_slh_dsa", "El paquete declara un checkpoint pero no trae su clave pública o su firma");
        }
        else {
            const blockHashes = allBlocks.map((b) => b.block_hash);
            const expectedRoot = mtDual1024(canonicalBytes({ block_hashes: blockHashes, chain_id: chain }), CHECKPOINT_DOMAIN);
            if (checkpoint.root !== expectedRoot || checkpoint.block_count !== blockHashes.length) {
                fail("checkpoint_slh_dsa", "La raíz del checkpoint no coincide con los bloques del paquete");
            }
            else if (!verifySlhDsaShake256s(ckptKey, Buffer.from(checkpoint.root, "utf8"), Buffer.from(checkpoint.signature, "base64"))) {
                fail("checkpoint_slh_dsa", "La firma SLH-DSA-SHAKE-256s del checkpoint no verifica");
            }
            else {
                components.set("checkpoint_slh_dsa", "OK");
            }
        }
    }
    // --- Veredicto estructurado de atribución (integridad ≠ atribución) ---
    let attribution;
    if (manifestAnchorFailed) {
        // F-ADV-02: se aportó un ancla de manifiesto y el juicio la
        // contradice (o el paquete no trae la cadena que el ancla exige
        // contrastar). La atribución no queda «no establecida»: queda
        // RECHAZADA. UNANCHORED se reserva para «no se aportó ancla».
        components.set("validator_attribution", "FAIL", "Se aportó un ancla de manifiesto y el juicio la contradice: la atribución de finalidad queda rechazada");
        attribution = {
            status: "INVALID",
            from_height: chainJudgment?.bootstrap?.bootstrap_height ?? 0,
            detail: "El ancla de manifiesto aportada contradice la cadena presentada, o el paquete no trae la cadena que el ancla exige contrastar: atribución rechazada",
        };
    }
    else if (!chainJudgment) {
        // Sin cadena, la atribución descansa en el manifiesto autodeclarado
        // y en sus certificados: si esa evidencia TAMPOCO verifica, la
        // atribución queda rechazada, no meramente no anclada (XM-07).
        const flatBasisFailed = components.all.some((c) => (c.name === "validator_manifest" || c.name === "finality_certificates") && c.status === "FAIL");
        if (flatBasisFailed) {
            components.set("validator_attribution", "FAIL", "Sin cadena de manifiestos y con la evidencia de finalidad del propio paquete rechazada (su manifiesto plano o sus certificados no verifican): la atribución queda rechazada");
            attribution = {
                status: "INVALID",
                from_height: 0,
                detail: "Sin cadena de manifiestos, la atribución descansa en el manifiesto autodeclarado y sus certificados, que no verifican: atribución rechazada",
            };
        }
        else {
            components.set("validator_attribution", "SKIPPED", "Sin cadena de manifiestos: la atribución de finalidad descansa solo en el manifiesto autodeclarado del paquete y no está anclada");
            attribution = {
                status: "UNANCHORED",
                from_height: 0,
                detail: "El paquete no trae cadena de manifiestos: atribución no anclada (manifiesto autodeclarado)",
            };
        }
    }
    else if (chainJudgment.errors.length > 0) {
        components.set("validator_attribution", "FAIL", "La cadena de manifiestos no verifica: la atribución de finalidad queda rechazada");
        attribution = {
            status: "INVALID",
            from_height: chainJudgment.bootstrap?.bootstrap_height ?? 0,
            detail: "La cadena de manifiestos presentada no verifica",
        };
    }
    else if (flatCrossFailed) {
        components.set("validator_attribution", "FAIL", "El manifiesto presentado contradice el manifiesto vigente de su propia cadena anclada: la atribución queda rechazada");
        attribution = {
            status: "INVALID",
            from_height: chainJudgment.bootstrap?.bootstrap_height ?? 0,
            detail: "El manifiesto del paquete no es el manifiesto vigente de la cadena anclada que el propio paquete presenta",
        };
    }
    else {
        const fromHeight = chainJudgment.bootstrap?.bootstrap_height ?? 0;
        if (fromHeight > 0) {
            components.set("validator_attribution", initialAnchorMatched ? "OK" : "SKIPPED", `PARTIAL FROM_HEIGHT ${fromHeight}: el bootstrap acredita la cadena solo desde la altura ${fromHeight}; la integridad anterior se verifica, la atribución no`);
            attribution = {
                status: "PARTIAL",
                from_height: fromHeight,
                detail: `La cadena acredita la atribución solo desde la altura ${fromHeight} (bootstrap de corte)`,
            };
        }
        else if (initialAnchorMatched) {
            components.set("validator_attribution", "OK", "Atribución anclada: H(M0) contrastada contra el ancla externa y cadena íntegra hasta el manifiesto vigente");
            attribution = {
                status: "ANCHORED",
                from_height: 0,
                detail: "Atribución anclada contra el ancla externa del manifiesto inicial",
            };
        }
        else {
            components.set("validator_attribution", "SKIPPED", "Cadena de manifiestos íntegra y encadenada, pero su raíz no se contrastó contra un valor externo: la integridad está probada, la atribución no");
            attribution = {
                status: "UNANCHORED",
                from_height: 0,
                detail: "Cadena íntegra por dentro, raíz no contrastada contra un valor externo",
            };
        }
    }
    const verdict = components.hasFail() ? "INVALID" : components.hasMissing() ? "INCOMPLETE" : "VALID";
    return {
        verdict,
        brick_number: subjectBrick,
        height,
        components: components.all,
        errors,
        ...(attribution ? { attribution } : {}),
    };
}
/* ================================================================== */
/* Paso A5 · Verificador independiente de paquetes del puente          */
/* MT-BRIDGE-PROOF-1 (frontera DIF/SCH entre superficies).             */
/*                                                                     */
/* Este verificador juzga la evidencia de cruce SIN importar           */
/* src/bridge.ts, src/foreign-sim.ts ni src/oplog.ts: reimplementa     */
/* los núcleos y las huellas desde los objetos del paquete, como la    */
/* ruta de ladrillos hace con los bloques. Comparte solo primitivas,   */
/* la doctrina de esquema (fuente única src/schema.ts) y               */
/* verifyCertificate, igual que la ruta MT-BRICK-PROOF-1.              */
/*                                                                     */
/* La extranjera del paquete es FOREIGN-SIM-1, SIMULADA y local: el    */
/* paquete debe declararlo en su etiqueta; un paquete que pretendiera  */
/* otra cosa se rechaza. El veredicto prueba la coherencia de la       */
/* evidencia de cruce entre las superficies (casa ↔ extranjera ↔ este  */
/* verificador), nunca la existencia de una cadena externa real.       */
/*                                                                     */
/* Componentes: format, chain_id, label, validator_manifest,           */
/* lock_proof, lock_checkpoint, foreign_records, burn_proof (SKIPPED   */
/* si el paquete no trae quema: el retorno no se juzga a medias) y     */
/* cross_surface (la copia extranjera corrobora la envuelta del        */
/* bloqueo exacto: mismo op_seq, misma huella de registro, mismo       */
/* titular fijado). La raíz de bloques del checkpoint queda atestada   */
/* por su firma SLH-DSA: el paquete no trae bloques contra los que     */
/* recomputarla (la misma posición declarada de verifyStateCheckpoint */
/* sin blockHashes).                                                   */
/* ================================================================== */
const BRIDGE_PACKAGE_FORMAT = "MT-BRIDGE-PROOF-1";
const LOCK_PROOF_FORMAT = "MT-BRIDGE-LOCK-PROOF-1";
const BURN_PROOF_FORMAT = "MT-FOREIGN-BURN-PROOF-1";
const FOREIGN_CHAIN_ID_V = "FOREIGN-SIM-1";
const FOREIGN_LABEL_V = "SIMULATED_FOREIGN_CHAIN";
const ENTRY_HASH_DOMAIN_V = "MT-OPLOG-ENTRY-1";
const FOREIGN_RECORD_DOMAIN = "MT-FOREIGN-SIM-1";
const BURN_PROOF_DOMAIN_V = "MT-BRIDGE-BURN-PROOF-1";
const OPLOG_TRANSITION_KIND = {
    TRANSFER: "OPLOG_TRANSFER",
    BRIDGE_LOCK: "OPLOG_BRIDGE_LOCK",
    BRIDGE_UNLOCK: "OPLOG_BRIDGE_UNLOCK",
};
export function verifyBridgeProof(pkgInput) {
    const components = new Components();
    const errors = [];
    const fail = (component, msg) => {
        components.set(component, "FAIL", msg);
        errors.push(`${component}: ${msg}`);
    };
    const missing = (component, msg) => {
        components.set(component, "MISSING", msg);
        errors.push(`${component}: ${msg}`);
    };
    if (!isObj(pkgInput)) {
        components.set("format", "FAIL", "El paquete no es un objeto JSON");
        return { verdict: "NOT_VERIFIABLE", components: components.all, errors: ["El paquete no es un objeto JSON"] };
    }
    const pkg = pkgInput;
    if (pkg.format !== BRIDGE_PACKAGE_FORMAT) {
        components.set("format", "FAIL", `Formato no reconocido: ${JSON.stringify(pkg.format)}`);
        return {
            verdict: "NOT_VERIFIABLE",
            components: components.all,
            errors: [`Formato de paquete no reconocido: ${JSON.stringify(pkg.format)}`],
        };
    }
    components.set("format", "OK");
    // Esquema cerrado del sobre (A5): el formato nace cerrado, sin legado;
    // ningún campo fuera de la lista se acepta ni se descarta en silencio.
    const pkgExtra = firstUnknownField(pkg, BRIDGE_PROOF_PACKAGE_FIELDS);
    if (pkgExtra !== null) {
        fail("format", schemaFieldNotAllowedMessage("el paquete MT-BRIDGE-PROOF-1", pkgExtra));
    }
    const chainId = pkg.chain_id;
    if (typeof chainId !== "string")
        missing("chain_id", "El paquete no declara chain_id");
    else if (chainId !== EXPECTED_CHAIN_ID)
        fail("chain_id", `Cadena inesperada: ${chainId}`);
    else
        components.set("chain_id", "OK");
    if (pkg.label !== FOREIGN_LABEL_V) {
        fail("label", `El paquete debe declarar la extranjera simulada (${FOREIGN_LABEL_V}); declara: ${JSON.stringify(pkg.label)}`);
    }
    else {
        components.set("label", "OK");
    }
    const manifest = pkg.validator_manifest;
    const manifestUsable = isObj(manifest) && Array.isArray(manifest.validators);
    if (!manifestUsable) {
        missing("validator_manifest", "El paquete no trae el manifiesto público de validadores");
    }
    else {
        const m = manifest;
        // Esquema cerrado sobre el manifiesto y sus entradas (A5, hallazgo
        // del fuzzing — errata 01): el manifiesto es evidencia que cruza
        // superficies; ningún campo extra se descarta en silencio y su
        // format se comprueba, como en el resto de objetos del paquete.
        if (m.format !== "MT-VALIDATOR-MANIFEST-1") {
            fail("validator_manifest", `El manifiesto no es un MT-VALIDATOR-MANIFEST-1 (format=${JSON.stringify(m.format)})`);
        }
        const mExtra = firstUnknownField(m, VALIDATOR_MANIFEST_FIELDS);
        if (mExtra !== null) {
            fail("validator_manifest", schemaFieldNotAllowedMessage("el manifiesto de validadores del paquete", mExtra));
        }
        m.validators.forEach((ve, i) => {
            if (!isObj(ve)) {
                fail("validator_manifest", `La entrada de validador ${i} del manifiesto no es un objeto`);
                return;
            }
            const veExtra = firstUnknownField(ve, VALIDATOR_MANIFEST_ENTRY_FIELDS);
            if (veExtra !== null) {
                fail("validator_manifest", schemaFieldNotAllowedMessage(`la entrada de validador ${i} del manifiesto`, veExtra));
            }
        });
        // Unicidad de validator_id (F-A6-03, corrección A6): las entradas se
        // consumen por primera coincidencia; un id duplicado es INVALID en
        // ambas rutas, no solo en la de ladrillos (equivalencia DIF).
        const seenIds = new Set();
        for (const ve of m.validators) {
            if (isObj(ve) && typeof ve.validator_id === "string") {
                if (seenIds.has(ve.validator_id)) {
                    fail("validator_manifest", `validator_id duplicado en el manifiesto: ${ve.validator_id}`);
                }
                seenIds.add(ve.validator_id);
            }
        }
        if (m.chain_id !== chainId) {
            fail("validator_manifest", "El manifiesto es de otra cadena");
        }
        else if (m.quorum !== 3 || m.validators.length !== 4) {
            fail("validator_manifest", `El manifiesto no declara 4 validadores con quórum 3 (quórum=${m.quorum}, n=${m.validators.length})`);
        }
        if (!components.all.some((c) => c.name === "validator_manifest" && c.status === "FAIL")) {
            components.set("validator_manifest", "OK");
        }
    }
    // --- Cadena de manifiestos (MT-VALIDATOR-MANIFEST-CHAIN-1, cierre
    // F-A6-01): misma doctrina que la ruta de ladrillos. Esta ruta no
    // tiene canal de anclas externas ni génesis contra el que contrastar
    // el bootstrap: la cadena se juzga por dentro, el manifiesto plano se
    // cruza contra su manifiesto vigente, y la atribución queda
    // declarada NO anclada en esta ruta. El certificado del bloqueo se
    // sigue juzgando contra el manifiesto plano ya cruzado.
    const bridgeSection = pkg.manifest_chain;
    if (bridgeSection !== undefined && bridgeSection !== null) {
        const judgment = judgeManifestChain(bridgeSection, {
            chainId: typeof chainId === "string" ? chainId : "",
        });
        if (judgment.errors.length > 0) {
            fail("validator_manifest_chain", judgment.errors.join("; "));
            components.set("validator_attribution", "FAIL", "La cadena de manifiestos no verifica: la atribución queda rechazada");
        }
        else {
            components.set("validator_manifest_chain", "OK", "Cadena de manifiestos íntegra: bootstrap coherente, encadenamiento sin huecos, posesión y autorización de cada transición verificadas");
            if (manifestUsable && judgment.current && !flatMatchesChained(manifest, judgment.current)) {
                fail("validator_manifest_chain", `${MANIFEST_CHAIN_MISMATCH}: el manifiesto presentado no coincide con el manifiesto vigente de la cadena de manifiestos del paquete (H del vigente: ${judgment.currentHash})`);
            }
            components.set("validator_attribution", "SKIPPED", "Esta ruta no contrasta la raíz de la cadena contra un valor externo: la atribución se declara no anclada aquí (la ruta de ladrillos con initial_validator_manifest_hash sí la ancla)");
        }
    }
    else {
        components.set("validator_manifest_chain", "SKIPPED", "El paquete no trae cadena de manifiestos (formato previo a MT-VALIDATOR-MANIFEST-CHAIN-1): su manifiesto es autodeclarado y la atribución de finalidad NO está anclada");
        components.set("validator_attribution", "SKIPPED", "Sin cadena de manifiestos: la atribución descansa solo en el manifiesto autodeclarado del paquete");
    }
    // --- Prueba de bloqueo: sobre, registro, certificado y checkpoint ---
    const lockProof = pkg.lock_proof;
    let entry;
    if (!isObj(lockProof)) {
        missing("lock_proof", "El paquete no trae la prueba de bloqueo MT-BRIDGE-LOCK-PROOF-1");
        components.set("lock_checkpoint", "MISSING", "Sin prueba de bloqueo no hay checkpoint que juzgar");
    }
    else {
        const lpExtra = firstUnknownField(lockProof, BRIDGE_LOCK_PROOF_FIELDS);
        if (lpExtra !== null) {
            fail("lock_proof", schemaFieldNotAllowedMessage("la prueba MT-BRIDGE-LOCK-PROOF-1 del paquete", lpExtra));
        }
        if (lockProof.format !== LOCK_PROOF_FORMAT || lockProof.label !== FOREIGN_LABEL_V) {
            fail("lock_proof", "La prueba de bloqueo no es un MT-BRIDGE-LOCK-PROOF-1 de la extranjera simulada");
        }
        const rawEntry = lockProof.entry;
        if (!isObj(rawEntry)) {
            fail("lock_proof", "La prueba de bloqueo no trae el registro BRIDGE_LOCK del diario");
        }
        else {
            const entryExtra = firstUnknownField(rawEntry, OPLOG_ENTRY_FIELDS);
            if (entryExtra !== null) {
                fail("lock_proof", schemaFieldNotAllowedMessage("el registro MT-OPLOG-1 de la prueba", entryExtra));
            }
            entry = rawEntry;
            if (entry.kind !== "BRIDGE_LOCK") {
                fail("lock_proof", `El registro de la prueba es de tipo ${JSON.stringify(entry.kind)}, no BRIDGE_LOCK`);
            }
            // Huella del registro recomputada desde su núcleo (reimplementado).
            try {
                const core = {
                    brick_number: entry.brick_number,
                    from_commitment: entry.from_commitment,
                    kind: entry.kind,
                    op_seq: entry.op_seq,
                    prev_oplog_hash: entry.prev_oplog_hash,
                    price_cents: entry.price_cents,
                    to_commitment: entry.to_commitment,
                };
                if (entry.reference !== undefined)
                    core.reference = entry.reference;
                const recomputed = mtDual1024(canonicalBytes(core), ENTRY_HASH_DOMAIN_V);
                if (recomputed !== entry.entry_hash) {
                    fail("lock_proof", "La huella del registro BRIDGE_LOCK no coincide con su contenido (registro alterado)");
                }
            }
            catch (e) {
                fail("lock_proof", `El registro BRIDGE_LOCK no se puede canonicalizar: ${e instanceof Error ? e.message : String(e)}`);
            }
            // Certificado de finalidad y su correspondencia con ESTE registro.
            // La evaluación va envuelta (A5, hallazgo del fuzzing — errata 01):
            // un certificado malformado (transición o votos borrados, entradas
            // nulas) debe producir un FAIL, nunca una excepción del verificador.
            if (!isObj(entry.finality)) {
                fail("lock_proof", "El registro no trae certificado de finalidad");
            }
            else {
                try {
                    const expectedTransition = {
                        chain_id: typeof chainId === "string" ? chainId : "",
                        kind: OPLOG_TRANSITION_KIND[entry.kind] ?? "",
                        sequence: entry.op_seq,
                        prev_state: entry.prev_oplog_hash,
                        transition_hash: entry.entry_hash,
                    };
                    if (canonicalize(entry.finality.transition) !== canonicalize(expectedTransition)) {
                        fail("lock_proof", "El certificado de finalidad no corresponde a este registro");
                    }
                    if (manifestUsable) {
                        const vc = judgeV1Certificate(manifest, entry.finality);
                        if (!vc.valid) {
                            fail("lock_proof", `Certificado de finalidad inválido (${vc.errors.join("; ")})`);
                        }
                    }
                }
                catch (e) {
                    fail("lock_proof", `El certificado de finalidad no se puede evaluar (${e instanceof Error ? e.message : String(e)})`);
                }
            }
            if (!components.all.some((c) => c.name === "lock_proof" && c.status === "FAIL")) {
                components.set("lock_proof", "OK");
            }
        }
        // Checkpoint que cubre el bloqueo (raíz de bloques atestada por la
        // firma: el paquete no trae los bloques de casa).
        const checkpoint = lockProof.checkpoint;
        if (!isObj(checkpoint)) {
            missing("lock_checkpoint", "La prueba de bloqueo no trae el checkpoint de casa");
        }
        else {
            const ckExtra = firstUnknownField(checkpoint, STATE_CHECKPOINT_FIELDS);
            if (ckExtra !== null) {
                fail("lock_checkpoint", schemaFieldNotAllowedMessage("el checkpoint MT-STATE-CHECKPOINT-1 de la prueba", ckExtra));
            }
            else if (checkpoint.format !== CHECKPOINT_STATE_FORMAT ||
                checkpoint.version !== CHECKPOINT_STATE_VERSION ||
                checkpoint.chain_id !== chainId) {
                fail("lock_checkpoint", "El checkpoint no es un MT-STATE-CHECKPOINT-1 de esta cadena");
            }
            else if (typeof checkpoint.latest_brick !== "number" ||
                !Number.isSafeInteger(checkpoint.latest_brick) ||
                checkpoint.latest_brick < 0 ||
                typeof checkpoint.latest_op_seq !== "number" ||
                !Number.isSafeInteger(checkpoint.latest_op_seq) ||
                typeof checkpoint.oplog_merkle_root !== "string" ||
                typeof checkpoint.block_root !== "string" ||
                typeof checkpoint.state_root !== "string" ||
                typeof checkpoint.epoch !== "number" ||
                typeof checkpoint.timestamp_ms !== "number" ||
                typeof checkpoint.checkpoint_public_key !== "string" ||
                typeof checkpoint.signature !== "string" ||
                typeof checkpoint.ecola_root !== "string" ||
                typeof checkpoint.ecola_count !== "number" ||
                typeof checkpoint.ecola_last_seq !== "number") {
                fail("lock_checkpoint", "El checkpoint tiene campos malformados");
            }
            else {
                const expectedStateRoot = mtDual1024(canonicalBytes({
                    block_root: checkpoint.block_root,
                    chain_id: chainId,
                    height: checkpoint.latest_brick,
                    last_op_seq: checkpoint.latest_op_seq,
                    oplog_merkle_root: checkpoint.oplog_merkle_root,
                }), CHECKPOINT_STATE_DOMAIN);
                if (expectedStateRoot !== checkpoint.state_root) {
                    fail("lock_checkpoint", "La raíz de estado del checkpoint no es la función pública de sus componentes declarados");
                }
                else {
                    const coreBytes = canonicalBytes({
                        block_root: checkpoint.block_root,
                        chain_id: checkpoint.chain_id,
                        checkpoint_public_key: checkpoint.checkpoint_public_key,
                        ecola_count: checkpoint.ecola_count,
                        ecola_last_seq: checkpoint.ecola_last_seq,
                        ecola_root: checkpoint.ecola_root,
                        epoch: checkpoint.epoch,
                        format: checkpoint.format,
                        latest_brick: checkpoint.latest_brick,
                        latest_op_seq: checkpoint.latest_op_seq,
                        oplog_merkle_root: checkpoint.oplog_merkle_root,
                        state_root: checkpoint.state_root,
                        timestamp_ms: checkpoint.timestamp_ms,
                        version: checkpoint.version,
                    });
                    let sigOk = false;
                    try {
                        sigOk = verifySlhDsaShake256s(checkpoint.checkpoint_public_key, coreBytes, Buffer.from(checkpoint.signature, "base64"));
                    }
                    catch {
                        sigOk = false;
                    }
                    if (!sigOk) {
                        fail("lock_checkpoint", "La firma SLH-DSA-SHAKE-256s del checkpoint no verifica");
                    }
                    else if (entry && checkpoint.latest_op_seq < entry.op_seq) {
                        fail("lock_checkpoint", `El checkpoint cubre hasta el op_seq ${checkpoint.latest_op_seq} y el bloqueo es el op_seq ${entry.op_seq}`);
                    }
                    else {
                        components.set("lock_checkpoint", "OK", "Checkpoint verificado: raíz de estado recomputada y firma SLH-DSA válida; la raíz de bloques queda atestada por la firma (el paquete no trae bloques)");
                    }
                }
            }
        }
    }
    // --- Registros extranjeros exportados: integridad y replay de envueltas ---
    const records = pkg.foreign_records;
    let parsedRecords;
    const mintByBrick = new Map();
    if (!Array.isArray(records)) {
        missing("foreign_records", "El paquete no trae la copia de registros de la extranjera");
    }
    else if (records.length === 0) {
        fail("foreign_records", "La copia de registros está vacía: falta el génesis extranjero");
    }
    else {
        parsedRecords = records;
        let prev = ZERO_HASH_1024;
        let broken = false;
        parsedRecords.forEach((r, i) => {
            if (!isObj(r)) {
                fail("foreign_records", `El registro en posición ${i} no es un objeto JSON`);
                broken = true;
                return;
            }
            const recExtra = firstUnknownField(r, FOREIGN_RECORD_FIELDS);
            if (recExtra !== null) {
                fail("foreign_records", schemaFieldNotAllowedMessage("el registro extranjero del paquete", recExtra));
            }
            if (r.seq !== i)
                fail("foreign_records", `Registro en posición ${i} declara seq=${r.seq}`);
            if (r.prev_hash !== prev)
                fail("foreign_records", `Registro ${r.seq}: prev_hash no encadena con el registro anterior`);
            try {
                const recomputed = mtDual1024(canonicalBytes({ data: r.data, kind: r.kind, prev_hash: r.prev_hash, seq: r.seq }), FOREIGN_RECORD_DOMAIN);
                if (recomputed !== r.hash) {
                    fail("foreign_records", `Registro ${r.seq}: la huella MT-DUAL-1024 no coincide (contenido alterado)`);
                }
            }
            catch {
                fail("foreign_records", `Registro ${r.seq}: no se puede canonicalizar para recomputar su huella`);
            }
            prev = r.hash;
            if (isObj(r.data)) {
                if (r.kind === "WRAPPED_MINT" && typeof r.data.brick_number === "number") {
                    mintByBrick.set(r.data.brick_number, {
                        seq: r.seq,
                        lock_op_seq: r.data.lock_op_seq,
                        lock_entry_hash: r.data.lock_entry_hash,
                        holder: r.data.holder,
                    });
                }
            }
        });
        const g = parsedRecords[0];
        if (!broken && (!isObj(g) || g.kind !== "GENESIS" || !isObj(g.data) || g.data.chain_id !== FOREIGN_CHAIN_ID_V || g.data.label !== FOREIGN_LABEL_V)) {
            fail("foreign_records", "El génesis de la copia no declara FOREIGN-SIM-1 (SIMULATED_FOREIGN_CHAIN)");
        }
        if (!components.all.some((c) => c.name === "foreign_records" && c.status === "FAIL")) {
            components.set("foreign_records", "OK");
        }
    }
    // --- Prueba de quema: huella recomputada y registro exacto en la copia ---
    const burnProof = pkg.burn_proof;
    if (!("burn_proof" in pkg)) {
        // El campo es obligatorio en el formato (puede ser null): su ausencia
        // no equivale a «sin quema», es un paquete incompleto.
        missing("burn_proof", "El paquete no declara el campo burn_proof (debe venir, aunque sea null)");
    }
    else if (burnProof === null || burnProof === undefined) {
        components.set("burn_proof", "SKIPPED", "El paquete no trae prueba de quema: el retorno no se ejecutó o no se exportó; el desbloqueo no se juzga");
    }
    else if (!isObj(burnProof)) {
        fail("burn_proof", "La prueba de quema no es un objeto JSON");
    }
    else {
        const bpExtra = firstUnknownField(burnProof, FOREIGN_BURN_PROOF_FIELDS);
        if (bpExtra !== null) {
            fail("burn_proof", schemaFieldNotAllowedMessage("la prueba MT-FOREIGN-BURN-PROOF-1 del paquete", bpExtra));
        }
        if (burnProof.format !== BURN_PROOF_FORMAT ||
            burnProof.label !== FOREIGN_LABEL_V ||
            burnProof.foreign_chain_id !== FOREIGN_CHAIN_ID_V) {
            fail("burn_proof", "La prueba no es un MT-FOREIGN-BURN-PROOF-1 de FOREIGN-SIM-1");
        }
        try {
            const core = {
                brick_number: burnProof.brick_number,
                burn_record_hash: burnProof.burn_record_hash,
                burn_seq: burnProof.burn_seq,
                burner_account: burnProof.burner_account,
                foreign_chain_id: FOREIGN_CHAIN_ID_V,
                format: BURN_PROOF_FORMAT,
            };
            const recomputed = mtDual1024(canonicalBytes(core), BURN_PROOF_DOMAIN_V);
            if (recomputed !== burnProof.proof_hash) {
                fail("burn_proof", "La huella de la prueba de quema no coincide con su contenido");
            }
        }
        catch {
            fail("burn_proof", "La prueba de quema no se puede canonicalizar para recomputar su huella");
        }
        if (entry && burnProof.brick_number !== entry.brick_number) {
            fail("burn_proof", `La quema es del ladrillo ${JSON.stringify(burnProof.brick_number)}, no del bloqueado (${entry.brick_number})`);
        }
        if (parsedRecords) {
            const seq = burnProof.burn_seq;
            const rec = typeof seq === "number" && Number.isSafeInteger(seq) ? parsedRecords[seq] : undefined;
            if (!rec || !isObj(rec) || rec.kind !== "WRAPPED_BURN" || rec.hash !== burnProof.burn_record_hash) {
                fail("burn_proof", "La copia extranjera no contiene el registro de quema declarado por la prueba");
            }
            else if (!isObj(rec.data) || rec.data.brick_number !== burnProof.brick_number || rec.data.burner !== burnProof.burner_account) {
                fail("burn_proof", "El registro de quema de la copia no corresponde al ladrillo ni al quemador de la prueba");
            }
        }
        if (!components.all.some((c) => c.name === "burn_proof" && c.status === "FAIL")) {
            components.set("burn_proof", "OK");
        }
    }
    // --- Cruce entre superficies: la copia corrobora ESTE bloqueo ---
    if (!entry) {
        components.set("cross_surface", "SKIPPED", "Sin registro de bloqueo legible no hay cruce que juzgar");
    }
    else if (!parsedRecords) {
        components.set("cross_surface", "SKIPPED", "Sin copia de registros no hay cruce que juzgar");
    }
    else {
        const mint = mintByBrick.get(entry.brick_number);
        if (!mint) {
            fail("cross_surface", `La copia extranjera no corrobora ninguna acuñación de envuelta para el ladrillo ${entry.brick_number} (paquete exportado antes del wrap o registros ajenos al cruce)`);
        }
        else if (mint.lock_op_seq !== entry.op_seq || mint.lock_entry_hash !== entry.entry_hash) {
            fail("cross_surface", "La acuñación extranjera no corresponde a este registro de bloqueo (op_seq o huella distintos)");
        }
        else if (mint.holder !== entry.reference) {
            fail("cross_surface", "La envuelta no nació a favor de la cuenta que el bloqueo fijó");
        }
        else if (isObj(burnProof) &&
            typeof burnProof.burn_seq === "number" &&
            mint.seq >= burnProof.burn_seq) {
            fail("cross_surface", "La quema declarada no es posterior a la acuñación en la copia extranjera");
        }
        else {
            components.set("cross_surface", "OK", "La copia extranjera corrobora la envuelta de este bloqueo exacto, a la cuenta fijada");
        }
    }
    // F-20-03 (remediación C-AUD-20): el paquete de SOLO BLOQUEO
    // (burn_proof declarado null) es un caso PARCIAL —el bloqueo se
    // juzga, el retorno no— y no puede salir VALID pleno: la ruta de
    // atestación degrada su caso análogo (cadena de atestación parcial)
    // a INCOMPLETE, y quien lee solo el veredicto de nivel superior no
    // debe ver un cruce completo donde la quema nunca se juzgó. El
    // componente burn_proof sigue SKIPPED (nunca verificado a medias);
    // lo que se alinea es el veredicto agregado. Los demás SKIPPED de
    // esta ruta (la sección de cadena de manifiestos ausente en paquetes
    // legados, declarada) NO degradan: son alcance declarado del
    // paquete, no una mitad del cruce sin juzgar.
    const burnNotJudged = components.all.some((c) => c.name === "burn_proof" && c.status === "SKIPPED");
    const verdict = components.hasFail()
        ? "INVALID"
        : components.hasMissing() || burnNotJudged
            ? "INCOMPLETE"
            : "VALID";
    return {
        verdict,
        ...(entry ? { brick_number: entry.brick_number } : {}),
        components: components.all,
        errors,
    };
}
/* ================================================================== */
/* Evidencia de cadena de manifiestos MT-MANIFEST-CHAIN-PROOF-1        */
/* (verificador standalone).                                           */
/*                                                                     */
/* Juzga la evidencia completa de una sucesión de conjuntos: la        */
/* cadena de manifiestos (juicio propio, el mismo de las rutas de      */
/* paquetes), el encadenamiento de sus bloques de evidencia, que el    */
/* bloque que introduce una transición comprometa EXACTAMENTE su       */
/* huella, y la finalidad de cada bloque en o tras el corte del        */
/* bootstrap, despachada por la altura de activación v2 declarada en   */
/* el propio bootstrap (F-ADV-01): v1 admisible solo antes de la       */
/* activación y juzgado contra el manifiesto EN VIGOR en su altura;    */
/* v2 obligatorio desde la activación; una versión incoherente con la  */
/* activación declarada se rechaza con su motivo fino (D3). Los        */
/* bloques anteriores al corte se verifican en integridad              */
/* (encadenamiento y huellas) pero su finalidad NO se juzga: la        */
/* atribución es PARTIAL desde el corte y el veredicto lo declara.     */
/* Las anclas del llamante (ProofAnchors) contrastan el génesis, la    */
/* raíz H(M0), el bootstrap entero (bootstrap_hash, remediación        */
/* C-AUD-20 F-20-01) y —como acelerador— el manifiesto vigente.        */
/* ================================================================== */
export function verifyManifestChainProof(pkgInput, anchors) {
    const components = new Components();
    const errors = [];
    const fail = (component, msg) => {
        components.set(component, "FAIL", msg);
        errors.push(`${component}: ${msg}`);
    };
    const missing = (component, msg) => {
        components.set(component, "MISSING", msg);
        errors.push(`${component}: ${msg}`);
    };
    if (!isObj(pkgInput)) {
        components.set("format", "FAIL", "El paquete no es un objeto JSON");
        return { verdict: "NOT_VERIFIABLE", components: components.all, errors: ["El paquete no es un objeto JSON"] };
    }
    const pkg = pkgInput;
    if (pkg.format !== MANIFEST_CHAIN_PROOF_FORMAT) {
        components.set("format", "FAIL", `Formato no reconocido: ${JSON.stringify(pkg.format)}`);
        return {
            verdict: "NOT_VERIFIABLE",
            components: components.all,
            errors: [`Formato de paquete no reconocido: ${JSON.stringify(pkg.format)}`],
        };
    }
    components.set("format", "OK");
    const pkgExtra = firstUnknownField(pkg, MANIFEST_CHAIN_PROOF_FIELDS);
    if (pkgExtra !== null)
        fail("format", schemaFieldNotAllowedMessage("el paquete MT-MANIFEST-CHAIN-PROOF-1", pkgExtra));
    const policy = networkPolicy(pkg.network_id);
    if (!policy) {
        fail("chain_id", `Red sin política autenticada en este verificador: ${JSON.stringify(pkg.network_id)}`);
    }
    else if (pkg.chain_id !== policy.chain_id) {
        fail("chain_id", `El paquete declara chain_id=${JSON.stringify(pkg.chain_id)} pero su red (${policy.network_id}) es la cadena ${policy.chain_id}`);
    }
    else {
        components.set("chain_id", "OK");
    }
    const blocks = pkg.blocks;
    if (!Array.isArray(blocks))
        missing("manifest_chain_blocks", "El paquete no trae la lista de bloques de evidencia");
    const genesisHash = Array.isArray(blocks) && isObj(blocks[0]) ? blocks[0].block_hash : undefined;
    // --- La cadena de manifiestos (juicio propio) ---
    const judgment = judgeManifestChain({ bootstrap: pkg.bootstrap, manifests: pkg.manifests, transitions: pkg.transitions }, { chainId: typeof pkg.chain_id === "string" ? pkg.chain_id : "", ...(genesisHash ? { genesisHash } : {}) });
    if (judgment.errors.length > 0) {
        fail("validator_manifest_chain", judgment.errors.join("; "));
    }
    else {
        components.set("validator_manifest_chain", "OK", "Cadena de manifiestos íntegra: bootstrap coherente, encadenamiento sin huecos, posesión y autorización de cada transición verificadas");
    }
    // --- Anclas del llamante ---
    let initialAnchorMatched = false;
    const anyAnchor = anchors &&
        (anchors.genesis_block_hash !== undefined ||
            anchors.initial_validator_manifest_hash !== undefined ||
            anchors.current_validator_manifest_hash !== undefined ||
            anchors.bootstrap_hash !== undefined);
    if (anyAnchor) {
        let anchorFailed = false;
        if (anchors.genesis_block_hash !== undefined) {
            if (!judgment.bootstrap || judgment.bootstrap.genesis_hash !== anchors.genesis_block_hash || genesisHash !== anchors.genesis_block_hash) {
                fail("manifest_anchor", "El génesis del paquete (bootstrap y/o primer bloque) NO coincide con el ancla externa aportada");
                anchorFailed = true;
            }
        }
        if (anchors.initial_validator_manifest_hash !== undefined) {
            if (!judgment.bootstrap || judgment.bootstrap.initial_manifest_hash !== anchors.initial_validator_manifest_hash) {
                fail("manifest_anchor", `${MANIFEST_CHAIN_MISMATCH}: el bootstrap presentado no es el publicado (initial_manifest_hash distinto del ancla externa)`);
                anchorFailed = true;
            }
            else if (judgment.hashes[0] !== anchors.initial_validator_manifest_hash) {
                fail("manifest_anchor", `${MANIFEST_CHAIN_MISMATCH}: H(M0) calculado no coincide con el ancla externa del manifiesto inicial`);
                anchorFailed = true;
            }
            else {
                initialAnchorMatched = true;
            }
        }
        if (anchors.current_validator_manifest_hash !== undefined) {
            if (!judgment.currentHash || judgment.currentHash !== anchors.current_validator_manifest_hash) {
                fail("manifest_anchor", `${MANIFEST_CHAIN_MISMATCH}: H del manifiesto vigente no coincide con el ancla actual aportada (acelerador discrepante)`);
                anchorFailed = true;
            }
        }
        if (anchors.bootstrap_hash !== undefined) {
            // F-20-01: H(bootstrap) compromete el bootstrap ENTERO — también
            // finality_activation_height, que H(M0) no cubre — contra el
            // bootstrap presentado. Si coincide y la cadena juzga íntegra, el
            // initial_manifest_hash declarado en él ES el publicado y H(M0)
            // ya quedó contrastado contra ese valor por el propio juicio de
            // la cadena: la raíz queda anclada también por esta vía.
            if (!judgment.bootstrap) {
                fail("bootstrap_anchor", `${MANIFEST_CHAIN_MISMATCH}: se aportó el ancla externa del bootstrap pero el paquete no trae bootstrap que contrastar`);
                anchorFailed = true;
            }
            else if (bootstrapHash(judgment.bootstrap) !== anchors.bootstrap_hash) {
                fail("bootstrap_anchor", `${MANIFEST_CHAIN_MISMATCH}: el bootstrap presentado no es el bootstrap publicado: H(bootstrap) no coincide con el ancla externa aportada. El hash del bootstrap compromete su contenido entero —también finality_activation_height, que H(M0) no cubre— (F-20-01)`);
                anchorFailed = true;
            }
            else {
                components.set("bootstrap_anchor", "OK", "H(bootstrap) calculado desde el bootstrap presentado coincide con el ancla externa aportada: el contenido entero del bootstrap —incluida finality_activation_height— es el publicado");
                if (judgment.errors.length === 0)
                    initialAnchorMatched = true;
            }
        }
        if (!anchorFailed)
            components.set("manifest_anchor", "OK", "El paquete coincide con todas las anclas de manifiesto aportadas");
    }
    else {
        components.set("manifest_anchor", "SKIPPED", "SIN ANCLA EXTERNA DE MANIFIESTO: la cadena se verifica por dentro (íntegra y encadenada) pero su raíz no se contrastó contra ningún valor publicado; aporta initial_validator_manifest_hash y bootstrap_hash del bootstrap publicado para anclar la atribución y el contenido entero del bootstrap");
    }
    if (judgment.bootstrap && anchors?.bootstrap_hash === undefined) {
        components.set("bootstrap_anchor", "SKIPPED", "La cadena de manifiestos es íntegra por dentro, pero el hash del bootstrap H(bootstrap) no se contrastó contra ningún valor externo: sin esa ancla, finality_activation_height y el resto del contenido del bootstrap quedan acreditados solo por la consistencia interna (F-20-01). Aporta bootstrap_hash del bootstrap publicado para anclarlos");
    }
    // --- Bloques de evidencia: encadenamiento, huellas, transiciones y finalidad ---
    let lastHeight = -1;
    if (Array.isArray(blocks)) {
        const transitions = Array.isArray(pkg.transitions) ? pkg.transitions : [];
        blocks.forEach((blockRaw, i) => {
            if (!isObj(blockRaw)) {
                fail("manifest_chain_blocks", `El bloque de evidencia ${i} no es un objeto`);
                return;
            }
            const block = blockRaw;
            const bExtra = firstUnknownField(blockRaw, MANIFEST_CHAIN_BLOCK_FIELDS);
            if (bExtra !== null)
                fail("manifest_chain_blocks", schemaFieldNotAllowedMessage(`el bloque de evidencia ${i}`, bExtra));
            if (block.height !== i)
                fail("manifest_chain_blocks", `El bloque en posición ${i} declara height=${JSON.stringify(block.height)}`);
            if (block.kind !== "GENESIS" && block.kind !== "MINT" && block.kind !== "VALIDATOR_SET_TRANSITION") {
                fail("manifest_chain_blocks", `El bloque ${i} declara un tipo no admitido: ${JSON.stringify(block.kind)}`);
            }
            if (i === 0 && block.prev_hash !== ZERO_HASH_1024)
                fail("manifest_chain_blocks", "El primer bloque de evidencia no encadena desde el hash cero");
            if (i > 0 && isObj(blocks[i - 1]) && block.prev_hash !== blocks[i - 1].block_hash) {
                fail("manifest_chain_blocks", `El bloque ${i} no encadena con el anterior (prev_hash distinto)`);
            }
            let recomputed;
            try {
                recomputed = manifestChainBlockHash({
                    height: block.height,
                    kind: block.kind,
                    prev_hash: block.prev_hash,
                    transition_hash: block.transition_hash,
                    payload_hash: block.payload_hash,
                });
            }
            catch (e) {
                fail("manifest_chain_blocks", `El bloque ${i} no se puede canonicalizar: ${e instanceof Error ? e.message : String(e)}`);
            }
            if (recomputed !== undefined && recomputed !== block.block_hash) {
                fail("manifest_chain_blocks", `La huella del bloque de evidencia ${i} no coincide con su contenido`);
            }
            if (typeof block.payload_hash !== "string" || !/^[0-9a-f]{256}$/.test(block.payload_hash)) {
                fail("manifest_chain_blocks", `El bloque ${i} no trae un payload_hash MT-DUAL-1024`);
            }
            // La transición que un bloque introduce queda comprometida por su
            // huella exacta; un bloque ordinario no compromete ninguna.
            if (block.kind === "VALIDATOR_SET_TRANSITION") {
                const t = transitions.find((tr) => isObj(tr) && tr.effective_height === block.height + 1);
                if (!t) {
                    fail("manifest_chain_blocks", `El bloque ${i} se declara de transición pero ninguna transición entra en vigor en la altura ${block.height + 1}`);
                }
                else {
                    let tHash;
                    try {
                        tHash = setTransitionHash(t);
                    }
                    catch {
                        tHash = undefined;
                    }
                    if (tHash === undefined || block.transition_hash !== tHash) {
                        fail("manifest_chain_blocks", `El bloque ${i} no compromete la huella exacta de la transición que introduce`);
                    }
                    if (t.transition_height !== block.height) {
                        fail("manifest_chain_blocks", `La transición comprometida por el bloque ${i} declara transition_height=${JSON.stringify(t.transition_height)}`);
                    }
                }
            }
            else if (block.transition_hash !== null) {
                fail("manifest_chain_blocks", `El bloque ${i} no es de transición pero compromete una transición`);
            }
            // Finalidad despachada por la altura de activación v2 DECLARADA
            // en el bootstrap presentado (F-ADV-01: el mismo despacho que la
            // ruta de ladrillos, y la altura declarada queda bajo el juicio):
            //  - altura < activación: el certificado debe ser v1 y se juzga
            //    contra el manifiesto EN VIGOR en su altura (operacionalizado),
            //    como en la ruta de ladrillos;
            //  - altura >= activación: el certificado debe ser v2 y se juzga
            //    con judgeV2Certificate contra el vigente en su altura;
            //  - una versión incoherente con la activación declarada (v1 en o
            //    tras la activación; v2 antes de ella) se rechaza con su
            //    motivo fino: así, corromper la altura declarada se detecta
            //    (FC-01: activación 0 → 1 sobre un génesis finalizado en v2).
            // Antes del corte del bootstrap la finalidad no se juzga
            // (atribución PARTIAL). Todo rechazo expone el motivo fino del
            // juicio correspondiente (D3): manifest_chain_blocks no enmascara
            // razones tras una puerta de forma genérica.
            const cut = judgment.bootstrap?.bootstrap_height ?? 0;
            if (typeof block.height === "number" && block.height >= cut) {
                const activation = judgment.bootstrap?.finality_activation_height;
                const descriptor = {
                    chain_id: pkg.chain_id,
                    kind: block.kind === "GENESIS" ? "GENESIS" : block.kind === "VALIDATOR_SET_TRANSITION" ? "VALIDATOR_SET_TRANSITION" : "MINT_BRICK",
                    sequence: block.height,
                    prev_state: block.prev_hash,
                    transition_hash: block.block_hash,
                };
                if (!isObj(block.finality)) {
                    fail("manifest_chain_blocks", `El bloque ${i} no trae certificado de finalidad`);
                }
                else if (isV2CertificateShape(block.finality)) {
                    if (activation !== undefined && block.height < activation) {
                        fail("manifest_chain_blocks", `El bloque ${i} trae un certificado MT-FINALITY-CERTIFICATE-2 en la altura ${block.height}, anterior a la activación de finalidad v2 declarada en el bootstrap (altura ${activation}): la versión del certificado no corresponde a la activación declarada`);
                    }
                    else if (judgment.errors.length === 0) {
                        const inForce = judgment.manifestAtHeight(block.height);
                        if (!inForce) {
                            fail("manifest_chain_blocks", `El bloque ${i} no tiene manifiesto en vigor en la cadena presentada`);
                        }
                        else {
                            const vErrs = judgeV2Certificate(inForce, block.finality, descriptor);
                            if (vErrs.length > 0)
                                fail("manifest_chain_blocks", `El certificado v2 del bloque ${i} no verifica: ${vErrs.join("; ")}`);
                        }
                    }
                }
                else if (activation !== undefined && block.height >= activation) {
                    fail("manifest_chain_blocks", `El bloque ${i} no trae un certificado MT-FINALITY-CERTIFICATE-2 en la altura ${block.height}, en o tras la activación de finalidad v2 declarada en el bootstrap (altura ${activation}): la finalidad v1 no es admisible desde la activación`);
                }
                else if (judgment.errors.length === 0) {
                    const inForce = judgment.manifestAtHeight(block.height);
                    if (!inForce) {
                        fail("manifest_chain_blocks", `El bloque ${i} no tiene manifiesto en vigor en la cadena presentada`);
                    }
                    else {
                        let descriptorOk = false;
                        try {
                            descriptorOk = canonicalize(block.finality.transition) === canonicalize(descriptor);
                        }
                        catch {
                            descriptorOk = false;
                        }
                        if (!descriptorOk) {
                            fail("manifest_chain_blocks", `El certificado v1 del bloque ${i} no corresponde a su transición`);
                        }
                        const vc = judgeV1Certificate(operationalManifest(inForce), block.finality);
                        if (!vc.valid) {
                            fail("manifest_chain_blocks", `El certificado v1 del bloque ${i} no verifica contra el manifiesto en vigor en su altura: ${vc.errors.join("; ")}`);
                        }
                    }
                }
            }
            if (typeof block.height === "number")
                lastHeight = block.height;
        });
        // Completitud de la evidencia (caso XC-01 del corpus adversarial):
        // cada transición de la sección debe quedar introducida por un
        // bloque PRESENTADO que comprometa su huella exacta. Una sección
        // que declara una transición cuyo bloque no viene en la evidencia
        // sobre-afirma la sucesión: la cadena se juzga íntegra por dentro,
        // pero la evidencia no demuestra que la transición ocurriera. (La
        // puerta de forma v1/v2 anterior a F-ADV-01 enmascaraba esta
        // ausencia rechazando esos paquetes por otra razón; con el despacho
        // corregido, la completitud se exige explícitamente.)
        if (judgment.errors.length === 0) {
            for (const tRaw of transitions) {
                if (!isObj(tRaw))
                    continue;
                const t = tRaw;
                let tHash;
                try {
                    tHash = setTransitionHash(t);
                }
                catch {
                    tHash = undefined;
                }
                const introducer = blocks.find((b) => isObj(b) && b.height === t.transition_height);
                if (!introducer ||
                    introducer.kind !== "VALIDATOR_SET_TRANSITION" ||
                    tHash === undefined ||
                    introducer.transition_hash !== tHash) {
                    fail("manifest_chain_blocks", `La evidencia no incluye el bloque de la altura ${JSON.stringify(t.transition_height)} introduciendo la transición a la época ${JSON.stringify(t.new_epoch)} y comprometiéndola: la sucesión declarada no está evidenciada completa`);
                }
            }
        }
        if (!components.all.some((c) => c.name === "manifest_chain_blocks" && c.status === "FAIL")) {
            components.set("manifest_chain_blocks", "OK");
        }
    }
    // --- Veredicto estructurado de atribución ---
    let attribution;
    const fromHeight = judgment.bootstrap?.bootstrap_height ?? 0;
    if (components.hasFail()) {
        components.set("validator_attribution", "FAIL", "La evidencia no verifica: la atribución de finalidad queda rechazada");
        attribution = { status: "INVALID", from_height: fromHeight, detail: "La evidencia de la cadena de manifiestos no verifica" };
    }
    else if (fromHeight > 0) {
        components.set("validator_attribution", initialAnchorMatched ? "OK" : "SKIPPED", `PARTIAL FROM_HEIGHT ${fromHeight}: la cadena acredita la atribución solo desde la altura ${fromHeight}; antes, la integridad se verifica y la atribución no`);
        attribution = { status: "PARTIAL", from_height: fromHeight, detail: `Atribución acreditada solo desde la altura ${fromHeight} (bootstrap de corte)` };
    }
    else if (initialAnchorMatched) {
        components.set("validator_attribution", "OK", "Atribución anclada contra el ancla externa del manifiesto inicial");
        attribution = { status: "ANCHORED", from_height: 0, detail: "Atribución anclada contra el ancla externa del manifiesto inicial" };
    }
    else {
        components.set("validator_attribution", "SKIPPED", "Cadena íntegra por dentro, raíz no contrastada contra un valor externo: integridad probada, atribución no anclada");
        attribution = { status: "UNANCHORED", from_height: 0, detail: "Cadena íntegra por dentro, raíz no contrastada contra un valor externo" };
    }
    const verdict = components.hasFail() ? "INVALID" : components.hasMissing() ? "INCOMPLETE" : "VALID";
    return {
        verdict,
        ...(lastHeight >= 0 ? { height: lastHeight } : {}),
        components: components.all,
        errors,
        ...(attribution ? { attribution } : {}),
    };
}
/* ================================================================== */
/* Hito D04 · Verificador independiente de paquetes empresariales      */
/* MT-ATTESTATION-PROOF-1 (capa OMTIVO, spec V2.1 §§5–10 y §28).       */
/*                                                                     */
/* Este juicio NO importa src/enterprise.ts (el productor): reimple-   */
/* menta desde los objetos del paquete las fórmulas de la spec —       */
/* H_MT (§5.1), compromisos (§5.2.1), mensaje firmado (§6.2), árbol     */
/* de evidencias (§8) — y reutiliza los jueces internos de este        */
/* fichero para la cadena de bloques, la cadena de manifiestos y la    */
/* finalidad. La batería 21 cruza productor ↔ verificador en cada      */
/* caso: una divergencia es un fallo.                                  */
/*                                                                     */
/* El paquete DEBE incrustar la prueba de la cadena de manifiestos     */
/* (exigencia del diseño adjudicado y del cierre F-A6-01): sin ella    */
/* el paquete está INCOMPLETE, no «válido sin anclar».                 */
/*                                                                     */
/* El veredicto trae resultados ESTRUCTURADOS por predicado (spec      */
/* §10.1 y §28): cada predicado reclamado se afirma (PASS), se niega   */
/* (FAIL) o se declara no comprobado (NOT_CHECKED) con su alcance      */
/* exacto («proves only»). NUNCA un verified:true genérico: la         */
/* integridad del paquete no es la verdad de su contenido, una firma   */
/* válida no es un contenido correcto, y el estado ACTUAL del          */
/* registro (revocaciones, checkpoints posteriores) no es conocible    */
/* offline: CURRENT_STATE_UNKNOWN viaja siempre en el mapa.            */
/*                                                                     */
/* Componentes: format, chain_id, manifest_schema, manifest_canonical, */
/* claims, key_registry, signature_set, artifact_digest,               */
/* package_integrity, record_commitment, evidence_inclusion,           */
/* checkpoint, checkpoint_finality, checkpoint_archive, genesis,       */
/* constitution_anchor, validator_manifest, validator_manifest_chain,  */
/* validator_manifest_anchor, current_manifest_anchor, bootstrap_anchor,*/
/* external_anchor,*/
/* block_linkage, block_fingerprints, validator_signatures,            */
/* finality_certificates, chain_tip_binding, audit_trail,              */
/* validator_attribution.                                              */
/* ================================================================== */
const ATTESTATION_FORMAT = "MT-ATTESTATION-PROOF-1";
const ATTESTATION_CHAIN_ID = "million-tower-testnet-1";
/** H_MT de la spec empresarial §5.1 (marco dominio‖0x00‖UINT64_BE(len)‖datos). */
function attHMt(domain, data) {
    const bytes = typeof data === "string" ? Buffer.from(data, "utf8") : Buffer.from(data);
    const len = Buffer.alloc(8);
    len.writeBigUInt64BE(BigInt(bytes.length));
    const frame = Buffer.concat([Buffer.from(domain, "utf8"), Buffer.from([0]), len, bytes]);
    return mtDual1024(frame);
}
function attIsDigest(v) {
    return typeof v === "string" && /^[0-9a-f]{256}$/.test(v);
}
function attHexBytes(hex) {
    if (typeof hex !== "string" || hex.length % 2 !== 0 || !/^[0-9a-f]*$/.test(hex))
        return null;
    return Buffer.from(hex, "hex");
}
const ATT_B64URL_RE = /^[A-Za-z0-9_-]+$/;
function attB64Url(value) {
    if (typeof value !== "string" || !ATT_B64URL_RE.test(value))
        return null;
    const buf = Buffer.from(value, "base64url");
    return buf.toString("base64url") === value ? buf : null;
}
function attUnknownField(obj, fields) {
    for (const k of Object.keys(obj))
        if (!fields.includes(k))
            return k;
    return null;
}
const ATT_ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z$/;
function attIsIso(v) {
    return typeof v === "string" && ATT_ISO_RE.test(v) && !Number.isNaN(Date.parse(v));
}
const ATT_UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
/** Catálogo cerrado de predicados (texto canónico «proves only», F2-12). */
const ATT_PREDICATES = {
    HASH_MATCH: { proves_only: "Que los bytes del artefacto producen exactamente la huella comprometida en el manifiesto." },
    FILE_SIZE: { proves_only: "Que la longitud en bytes del artefacto coincide con la declarada en el manifiesto." },
    SCHEMA_VALID: { proves_only: "Que el manifiesto cumple el esquema cerrado MT-EVIDENCE-MANIFEST-1 y su forma canónica JCS se reproduce byte a byte." },
    TIME_BOUND: { proves_only: "Que la atestación existía ya en el momento del checkpoint certificado que la incluye y que su instante declarado cae dentro de las cotas reclamadas." },
    MULTI_SIG: { proves_only: "Que al menos N claves distintas registradas del tenant firmaron el manifiesto en los roles exigidos." },
    TEST_SUITE_PASS: { proves_only: "Que existe un informe de pruebas comprometido por huella asociado a la evidencia de entrega." },
};
const ATT_ROLE_CONTEXT = {
    TENANT_OWNER: "MT-EVIDENCE-OWNER-V1",
    TENANT_ATTESTER: "MT-EVIDENCE-ATTESTER-V1",
};
const ATT_ROLE_PURPOSE = {
    TENANT_OWNER: "TENANT_OWNER_SIGNING",
    TENANT_ATTESTER: "TENANT_ATTESTER_SIGNING",
};
const ATT_MANIFEST_FIELDS = [
    "manifest_version", "chain_id", "tenant_ref", "record_id", "record_type",
    "artifact_id", "artifact_digest", "artifact_media_type", "byte_length",
    "confidentiality", "claims_digest", "created_at", "expires_at",
    "previous_record_id", "policy_id", "anchor_profile",
];
const ATT_KEY_FIELDS = [
    "key_id", "tenant_ref", "public_key", "algorithm", "purpose", "status",
    "created_at", "expires_at", "key_fingerprint", "pop_signature_b64u",
    "registration_statement_digest",
];
const ATT_SIGNATURE_FIELDS = ["signer_key_id", "role", "context", "signature_b64u", "signed_at"];
const ATT_CHECKPOINT_FIELDS = [
    "checkpoint_version", "network_id", "chain_id", "checkpoint_seq",
    "evidence_tree_size", "evidence_tree_root", "previous_checkpoint_digest",
    "tip_block_height", "tip_block_hash", "validator_set_id", "created_at",
];
const ATT_AUDIT_FIELDS = [
    "event_type", "occurred_at", "actor", "payload_digest",
    "record_event_index", "previous_record_event_digest", "record_event_digest",
];
/** Juicio de esquema cerrado del manifiesto (reimplementación del §5.2). */
function attJudgeManifest(m) {
    const errs = [];
    if (!isObj(m))
        return ["El manifiesto no es un objeto"];
    const unknown = attUnknownField(m, ATT_MANIFEST_FIELDS);
    if (unknown !== null)
        errs.push(`MT-EVIDENCE-MANIFEST-1: campo no permitido «${unknown}» (esquema cerrado)`);
    for (const f of ATT_MANIFEST_FIELDS)
        if (!(f in m))
            errs.push(`MT-EVIDENCE-MANIFEST-1: falta el campo «${f}»`);
    if (errs.length > 0)
        return errs;
    if (m.manifest_version !== "MT-EVIDENCE-MANIFEST-1")
        errs.push("manifest_version debe ser MT-EVIDENCE-MANIFEST-1");
    if (m.chain_id !== ATTESTATION_CHAIN_ID)
        errs.push(`chain_id debe ser ${ATTESTATION_CHAIN_ID}`);
    if (typeof m.tenant_ref !== "string" || !/^[0-9a-f]{64}$/.test(m.tenant_ref))
        errs.push("tenant_ref debe ser un seudónimo de 64 hex");
    if (typeof m.record_id !== "string" || !ATT_UUID_RE.test(m.record_id))
        errs.push("record_id debe ser un UUID");
    if (m.record_type !== "ATTESTATION")
        errs.push("record_type debe ser ATTESTATION en un paquete MT-ATTESTATION-PROOF-1");
    if (typeof m.artifact_id !== "string" || !/^[A-Za-z0-9._-]{1,128}$/.test(m.artifact_id))
        errs.push("artifact_id inválido");
    if (!attIsDigest(m.artifact_digest))
        errs.push("artifact_digest debe ser una huella de 256 hex");
    if (typeof m.artifact_media_type !== "string" || m.artifact_media_type.length > 128 || !/^[A-Za-z0-9!#$&^_.+-]+\/[A-Za-z0-9!#$&^_.+-]+$/.test(m.artifact_media_type))
        errs.push("artifact_media_type inválido");
    if (!Number.isSafeInteger(m.byte_length) || m.byte_length < 0 || m.byte_length > 100 * 1024 * 1024)
        errs.push("byte_length fuera de rango (0..100 MiB)");
    if (m.confidentiality !== "PUBLIC" && m.confidentiality !== "PRIVATE")
        errs.push("confidentiality debe ser PUBLIC o PRIVATE");
    if (!attIsDigest(m.claims_digest))
        errs.push("claims_digest debe ser una huella de 256 hex");
    if (!attIsIso(m.created_at))
        errs.push("created_at debe ser ISO-8601 UTC");
    if (m.expires_at !== null && (!attIsIso(m.expires_at) || m.expires_at <= m.created_at))
        errs.push("expires_at debe ser null o posterior a created_at");
    if (m.previous_record_id !== null && (typeof m.previous_record_id !== "string" || !ATT_UUID_RE.test(m.previous_record_id)))
        errs.push("previous_record_id debe ser null o UUID");
    if (typeof m.policy_id !== "string" || !/^[A-Za-z0-9._-]{1,64}$/.test(m.policy_id))
        errs.push("policy_id inválido");
    if (m.anchor_profile !== "ALTIVO_TESTNET")
        errs.push("anchor_profile debe ser ALTIVO_TESTNET");
    return errs;
}
/** Juicio de esquema cerrado de las claims (catálogo de predicados). */
function attJudgeClaims(claimsRaw) {
    const errors = [];
    const claimed = new Map();
    if (!Array.isArray(claimsRaw) || claimsRaw.length < 1 || claimsRaw.length > 16) {
        return { errors: ["claims debe ser un array de 1..16 afirmaciones"], claimed };
    }
    for (const raw of claimsRaw) {
        if (!isObj(raw)) {
            errors.push("Cada claim debe ser un objeto");
            continue;
        }
        const unknown = attUnknownField(raw, ["predicate_id", "parameters"]);
        if (unknown !== null) {
            errors.push(`claim: campo no permitido «${unknown}»`);
            continue;
        }
        const pid = raw.predicate_id;
        if (typeof pid !== "string" || !(pid in ATT_PREDICATES)) {
            errors.push(`predicate_id fuera del catálogo cerrado: ${JSON.stringify(pid)}`);
            continue;
        }
        if (claimed.has(pid)) {
            errors.push(`predicate_id duplicado: ${pid}`);
            continue;
        }
        const p = raw.parameters;
        if (!isObj(p)) {
            errors.push(`claim ${pid}: parameters debe ser un objeto`);
            continue;
        }
        if (pid === "HASH_MATCH" || pid === "FILE_SIZE" || pid === "SCHEMA_VALID") {
            const u = attUnknownField(p, []);
            if (u !== null)
                errors.push(`claim ${pid}: parámetro no permitido «${u}»`);
        }
        else if (pid === "TIME_BOUND") {
            const u = attUnknownField(p, ["not_before", "not_after"]);
            if (u !== null)
                errors.push(`claim TIME_BOUND: parámetro no permitido «${u}»`);
            else if (!attIsIso(p.not_before) || !attIsIso(p.not_after) || p.not_before >= p.not_after)
                errors.push("claim TIME_BOUND: se exige not_before < not_after en ISO-8601 UTC");
        }
        else if (pid === "MULTI_SIG") {
            const u = attUnknownField(p, ["min_signatures", "required_roles"]);
            if (u !== null)
                errors.push(`claim MULTI_SIG: parámetro no permitido «${u}»`);
            else {
                if (!Number.isSafeInteger(p.min_signatures) || p.min_signatures < 2 || p.min_signatures > 8)
                    errors.push("claim MULTI_SIG: min_signatures debe ser un entero 2..8");
                if (!Array.isArray(p.required_roles) || p.required_roles.length < 1)
                    errors.push("claim MULTI_SIG: required_roles no puede estar vacío");
                else {
                    const roles = new Set();
                    for (const r of p.required_roles) {
                        if (r !== "TENANT_OWNER" && r !== "TENANT_ATTESTER")
                            errors.push(`claim MULTI_SIG: rol no admitido ${JSON.stringify(r)}`);
                        if (roles.has(r))
                            errors.push("claim MULTI_SIG: required_roles duplicado");
                        roles.add(r);
                    }
                    if (Number.isSafeInteger(p.min_signatures) && p.min_signatures < p.required_roles.length)
                        errors.push("claim MULTI_SIG: min_signatures menor que los roles exigidos");
                }
            }
        }
        else if (pid === "TEST_SUITE_PASS") {
            const u = attUnknownField(p, ["report_digest"]);
            if (u !== null)
                errors.push(`claim TEST_SUITE_PASS: parámetro no permitido «${u}»`);
            else if (!attIsDigest(p.report_digest))
                errors.push("claim TEST_SUITE_PASS: report_digest debe ser una huella de 256 hex");
        }
        claimed.set(pid, p);
    }
    return { errors, claimed };
}
/* Árbol de evidencias §8: hoja H(0x00‖compromiso), nodo H(0x01‖izq‖der), MT-DUAL-1024 sin dominio. */
function attLeafHash(commitmentHex) {
    const bytes = attHexBytes(commitmentHex);
    if (!bytes || bytes.length !== 128)
        return null;
    return mtDual1024(Buffer.concat([Buffer.from([0]), bytes]));
}
function attNodeHash(leftHex, rightHex) {
    const l = attHexBytes(leftHex);
    const r = attHexBytes(rightHex);
    if (!l || !r || l.length !== 128 || r.length !== 128)
        return null;
    return mtDual1024(Buffer.concat([Buffer.from([1]), l, r]));
}
function attVerifyInclusion(commitmentHex, proofRaw, expectedRoot) {
    if (!isObj(proofRaw))
        return "La prueba de inclusión no es un objeto";
    const { leaf_index, tree_size, audit_path } = proofRaw;
    if (!Number.isSafeInteger(leaf_index) || !Number.isSafeInteger(tree_size) || !Array.isArray(audit_path)) {
        return "La prueba de inclusión no declara leaf_index/tree_size/audit_path válidos";
    }
    const li = leaf_index;
    let size = tree_size;
    if (li < 0 || li >= size)
        return "leaf_index fuera del tamaño del árbol declarado";
    const leaf0 = attLeafHash(commitmentHex);
    if (leaf0 === null)
        return "El compromiso del registro no es una huella de 128 bytes";
    let acc = leaf0;
    let idx = li;
    let p = 0;
    while (size > 1) {
        const siblingExists = idx % 2 === 0 ? idx + 1 < size : true;
        if (siblingExists) {
            const sib = audit_path[p++];
            if (typeof sib !== "string")
                return "El camino de auditoría se agota antes de llegar a la raíz";
            const next = idx % 2 === 0 ? attNodeHash(acc, sib) : attNodeHash(sib, acc);
            if (next === null)
                return "Un hash del camino de auditoría no es una huella de 128 bytes";
            acc = next;
        }
        idx = Math.floor(idx / 2);
        size = Math.ceil(size / 2);
    }
    if (p !== audit_path.length)
        return "El camino de auditoría trae hashes sobrantes";
    if (acc !== expectedRoot)
        return "La raíz recalculada desde la hoja y el camino NO coincide con la raíz del checkpoint";
    return null;
}
/** Mensaje firmado §6.2, reimplementado. */
function attSigningMessage(chainId, context, manifestDigestHex) {
    return Buffer.concat([
        Buffer.from("MT-SIGNED-STATEMENT-V1", "utf8"), Buffer.from([0]),
        Buffer.from(chainId, "utf8"), Buffer.from([0]),
        Buffer.from(context, "utf8"), Buffer.from([0]),
        Buffer.from(manifestDigestHex, "utf8"),
    ]);
}
/* ---- Tranche C2-2: juez de la sección MT-DELIVERY-EVIDENCE-1 (E25) y ---- */
/* ---- del sello temporal §9, reimplementados desde el paquete.       ---- */
function attSigMsg(context, core) {
    return Buffer.concat([Buffer.from(context, "utf8"), Buffer.from([0]), canonicalBytes(core)]);
}
function attVerifySectionSig(pub, context, core, sigB64u) {
    if (typeof pub !== "string" || typeof sigB64u !== "string")
        return false;
    const sig = attB64Url(sigB64u);
    if (sig === null)
        return false;
    try {
        return verifyMlDsa87(pub, attSigMsg(context, core), sig);
    }
    catch {
        return false;
    }
}
function attJudgeDeliverySection(section, expectedTenantRef, claimedReportDigest) {
    if (!isObj(section) || section.format !== "MT-DELIVERY-EVIDENCE-1" || !isObj(section.intent) || !isObj(section.evidence)) {
        return { status: "NOT_CHECKED", detail: "La sección de entrega del paquete no es MT-DELIVERY-EVIDENCE-1: TEST_SUITE_PASS no se afirma" };
    }
    const intent = section.intent;
    const ev = section.evidence;
    if (!isObj(intent.core))
        return { status: "FAIL", detail: "La intención de la sección de entrega no es un objeto" };
    const core = intent.core;
    if (attHMt("MT:SERVICE-INTENT:V1", canonicalBytes(core)) !== intent.intent_digest)
        return { status: "FAIL", detail: "intent_digest no reproduce desde el núcleo canónico de la intención" };
    if (!attVerifySectionSig(core.client_public_key, "MT-DELIVERY-INTENT-V1", core, intent.signature_b64u))
        return { status: "FAIL", detail: "La firma de la intención de servicio no verifica" };
    if (ev.intent_digest !== intent.intent_digest)
        return { status: "FAIL", detail: "La evidencia no enlaza con la intención firmada de la sección" };
    if (ev.tenant_ref !== expectedTenantRef)
        return { status: "FAIL", detail: "La evidencia de entrega es de otro tenant_ref: evidencia ajena a esta atestación" };
    if (ev.report_digest !== claimedReportDigest)
        return { status: "FAIL", detail: "El report_digest reclamado en la claim no coincide con el de la evidencia de entrega (evidencia contradictoria)" };
    if (!isObj(ev.test_report) || attHMt("MT:TEST-REPORT:V1", canonicalBytes(ev.test_report)) !== ev.report_digest)
        return { status: "FAIL", detail: "report_digest no reproduce desde el informe de pruebas canónico" };
    const partial = {
        format: ev.format, delivery_id: ev.delivery_id, contract_id: ev.contract_id, tenant_ref: ev.tenant_ref,
        intent_digest: ev.intent_digest, deliverable_digest: ev.deliverable_digest, test_report: ev.test_report,
        report_digest: ev.report_digest, delivered_at: ev.delivered_at, provider_key_id: ev.provider_key_id,
        provider_public_key: ev.provider_public_key,
    };
    if (!attVerifySectionSig(ev.provider_public_key, "MT-DELIVERY-V1", partial, ev.delivery_signature_b64u))
        return { status: "FAIL", detail: "La firma de entrega no verifica" };
    if (attHMt("MT:DELIVERY-EVIDENCE:V1", canonicalBytes({ ...partial, delivery_signature_b64u: ev.delivery_signature_b64u })) !== ev.evidence_digest)
        return { status: "FAIL", detail: "evidence_digest no reproduce" };
    if (ev.acceptance === null || ev.acceptance === undefined)
        return { status: "NOT_CHECKED", detail: "Entrega sin aceptación firmada del cliente: TEST_SUITE_PASS no se afirma" };
    const acc = ev.acceptance;
    const accCore = { delivery_id: ev.delivery_id, evidence_digest: ev.evidence_digest, accepted_at: acc.accepted_at, statement: acc.statement };
    if (!attVerifySectionSig(core.client_public_key, "MT-DELIVERY-ACCEPTANCE-V1", accCore, acc.signature_b64u))
        return { status: "FAIL", detail: "La firma de aceptación no verifica contra la clave del cliente de la intención" };
    const r = ev.test_report;
    if (r.total === 0)
        return { status: "FAIL", detail: "Informe vacío (total=0): no acredita paso de suite alguna" };
    if (r.failed !== 0 || r.passed !== r.total)
        return { status: "FAIL", detail: `Informe con fallos: passed=${r.passed} failed=${r.failed} total=${r.total}` };
    return { status: "PASS", detail: `Entrega aceptada con firma válida e informe íntegro: ${r.passed}/${r.total} pruebas, report_digest reproducido desde MT-DELIVERY-EVIDENCE-1` };
}
function attJudgeTimestampToken(pkg) {
    const token = pkg.timestamp_token;
    if (token === undefined || token === null)
        return null;
    if (!isObj(token))
        return { ok: false, detail: "timestamp_token no es un objeto" };
    const { tsa_public_key, signature_b64u, token_digest, ...core } = token;
    if (token_digest !== attHMt("MT:TIMESTAMP-TOKEN:V1", canonicalBytes({ ...core, tsa_public_key, signature_b64u })))
        return { ok: false, detail: "token_digest del sello temporal no reproduce" };
    if (!attVerifySectionSig(tsa_public_key, "MT-TIMESTAMP-TOKEN-V1", core, signature_b64u))
        return { ok: false, detail: "La firma del sello temporal no verifica" };
    if (core.message_imprint !== pkg.package_digest)
        return { ok: false, detail: "El sello enlaza otra huella (message_imprint ≠ package_digest)" };
    const manifest = pkg.manifest;
    if (typeof core.gen_time !== "string" || typeof manifest?.created_at !== "string" || core.gen_time < manifest.created_at)
        return { ok: false, detail: "gen_time del sello es anterior a created_at" };
    return { ok: true, detail: `INDEPENDENT_TIMESTAMP_VERIFIED: sello MT-TIMESTAMP-TOKEN-1 válido sobre package_digest (gen_time ${String(core.gen_time)}, TSA «${String(core.tsa_name)}»)` };
}
export function verifyAttestationProof(pkgInput, anchors) {
    const components = new Components();
    const errors = [];
    const fail = (component, msg) => {
        components.set(component, "FAIL", msg);
        errors.push(`${component}: ${msg}`);
    };
    const missing = (component, msg) => {
        components.set(component, "MISSING", msg);
        errors.push(`${component}: ${msg}`);
    };
    const predicates = {};
    const setPredicate = (id, status, detail) => {
        predicates[id] = {
            status,
            proves_only: id === "CURRENT_STATE_UNKNOWN"
                ? "Nada: el estado actual (revocaciones de claves, checkpoints posteriores, estado vivo del registro) no es conocible offline."
                : ATT_PREDICATES[id].proves_only,
            detail,
        };
    };
    for (const id of Object.keys(ATT_PREDICATES))
        setPredicate(id, "NOT_CHECKED", "No evaluado");
    setPredicate("CURRENT_STATE_UNKNOWN", "NOT_CHECKED", "Declaración obligatoria (§10.1): este juicio es sobre el paquete y su ancla, no sobre el estado actual del registro");
    if (!isObj(pkgInput)) {
        components.set("format", "FAIL", "El paquete no es un objeto JSON");
        return { verdict: "NOT_VERIFIABLE", components: components.all, errors: ["El paquete no es un objeto JSON"], predicates };
    }
    const pkg = pkgInput;
    if (pkg.format !== ATTESTATION_FORMAT) {
        components.set("format", "FAIL", `Formato no reconocido: ${JSON.stringify(pkg.format)}`);
        return { verdict: "NOT_VERIFIABLE", components: components.all, errors: [`Formato de paquete no reconocido: ${JSON.stringify(pkg.format)}`], predicates };
    }
    components.set("format", "OK");
    const chainId = pkg.chain_id;
    if (typeof chainId !== "string")
        missing("chain_id", "El paquete no declara chain_id");
    else if (chainId !== ATTESTATION_CHAIN_ID)
        fail("chain_id", `Cadena inesperada: ${chainId}`);
    else
        components.set("chain_id", "OK");
    // --- Presencia de piezas (sin esto no se puede decidir: INCOMPLETE) ---
    const manifestRaw = pkg.manifest;
    const claimsRaw = pkg.claims;
    const sigSetRaw = pkg.signature_set;
    const registryRaw = pkg.key_registry;
    const artifactRaw = pkg.artifact;
    const evidenceRaw = pkg.evidence;
    const auditRaw = pkg.audit_trail;
    const chainEvRaw = pkg.chain_evidence;
    if (!isObj(manifestRaw))
        missing("manifest_schema", "El paquete no trae el manifiesto");
    if (!Array.isArray(claimsRaw))
        missing("claims", "El paquete no trae las claims");
    if (!isObj(sigSetRaw))
        missing("signature_set", "El paquete no trae el conjunto de firmas");
    if (!Array.isArray(registryRaw))
        missing("key_registry", "El paquete no trae la instantánea del registro de claves");
    if (!isObj(artifactRaw))
        missing("artifact_digest", "El paquete no trae la sección del artefacto");
    if (!isObj(evidenceRaw))
        missing("record_commitment", "El paquete no trae la sección de evidencia");
    if (!Array.isArray(auditRaw))
        missing("audit_trail", "El paquete no trae el rastro de auditoría del registro");
    if (!isObj(chainEvRaw) || !isObj(chainEvRaw.genesis) || !Array.isArray(chainEvRaw.blocks) ||
        !isObj(chainEvRaw.validator_manifest) || !isObj(chainEvRaw.manifest_chain)) {
        missing("validator_manifest_chain", "El paquete no trae la evidencia de cadena completa (génesis, bloques, manifiesto y cadena de manifiestos): MT-ATTESTATION-PROOF-1 la exige incrustada");
    }
    if (components.hasMissing()) {
        return {
            verdict: components.hasFail() ? "INVALID" : "INCOMPLETE",
            components: components.all, errors, predicates,
            ...(typeof pkg.record_id === "string" ? { record_id: pkg.record_id } : {}),
        };
    }
    const manifest = manifestRaw;
    const evidence = evidenceRaw;
    const artifact = artifactRaw;
    const chainEv = chainEvRaw;
    // --- Manifiesto: esquema cerrado y forma canónica ---
    const manifestErrors = attJudgeManifest(manifest);
    if (manifestErrors.length > 0) {
        fail("manifest_schema", manifestErrors.join("; "));
    }
    else {
        components.set("manifest_schema", "OK");
    }
    let manifestCanonicalRecomputed = null;
    try {
        manifestCanonicalRecomputed = canonicalize(manifest);
    }
    catch {
        manifestCanonicalRecomputed = null;
    }
    if (typeof pkg.manifest_canonical !== "string" || manifestCanonicalRecomputed === null) {
        fail("manifest_canonical", "El paquete no trae la forma canónica declarada o el manifiesto no se puede canonicalizar");
    }
    else if (manifestCanonicalRecomputed !== pkg.manifest_canonical) {
        fail("manifest_canonical", "La forma canónica JCS recalculada NO coincide byte a byte con la declarada en el paquete");
    }
    else {
        components.set("manifest_canonical", "OK");
    }
    const manifestDigest = manifestCanonicalRecomputed !== null
        ? attHMt("MT:MANIFEST:V1", Buffer.from(manifestCanonicalRecomputed, "utf8"))
        : null;
    // --- Claims: esquema cerrado y compromiso ---
    const claimsJudgment = attJudgeClaims(claimsRaw);
    if (claimsJudgment.errors.length > 0) {
        fail("claims", claimsJudgment.errors.join("; "));
    }
    else {
        components.set("claims", "OK");
    }
    let claimsCommitment = null;
    try {
        claimsCommitment = attHMt("MT:CLAIMS:V1", canonicalBytes(claimsRaw));
    }
    catch {
        claimsCommitment = null;
    }
    if (claimsCommitment === null || manifest.claims_digest !== claimsCommitment) {
        fail("claims", "El compromiso de claims recalculado NO coincide con claims_digest del manifiesto");
    }
    // --- Registro de claves: forma, huellas, posesión y pertenencia ---
    const registry = new Map();
    let registryOk = true;
    registryRaw.forEach((entryRaw, i) => {
        if (!isObj(entryRaw)) {
            fail("key_registry", `La entrada ${i} del registro no es un objeto`);
            registryOk = false;
            return;
        }
        const unknown = attUnknownField(entryRaw, ATT_KEY_FIELDS);
        if (unknown !== null) {
            fail("key_registry", `La entrada ${i} del registro trae el campo no permitido «${unknown}»`);
            registryOk = false;
            return;
        }
        const e = entryRaw;
        if (typeof e.key_id !== "string" || registry.has(e.key_id)) {
            fail("key_registry", `key_id duplicado o inválido en la entrada ${i}`);
            registryOk = false;
            return;
        }
        if (e.tenant_ref !== manifest.tenant_ref) {
            fail("key_registry", `La clave ${e.key_id} no declara el tenant_ref del manifiesto`);
            registryOk = false;
        }
        if (e.algorithm !== "ML-DSA-87") {
            fail("key_registry", `La clave ${e.key_id} no es ML-DSA-87`);
            registryOk = false;
        }
        if (e.purpose !== "TENANT_OWNER_SIGNING" && e.purpose !== "TENANT_ATTESTER_SIGNING") {
            fail("key_registry", `La clave ${e.key_id} declara un propósito fuera de la capa de tenants`);
            registryOk = false;
        }
        if (typeof e.public_key !== "string" || !isMlDsa87PublicKey(e.public_key)) {
            fail("key_registry", `La clave pública de ${e.key_id} no tiene la forma ML-DSA-87`);
            registryOk = false;
        }
        const pubBytes = typeof e.public_key === "string" ? Buffer.from(e.public_key, "base64") : Buffer.alloc(0);
        const fingerprint = attHMt("MT:KEY:V1", pubBytes);
        if (e.key_fingerprint !== fingerprint) {
            fail("key_registry", `La huella de la clave ${e.key_id} no reproduce desde su clave pública`);
            registryOk = false;
        }
        if (typeof e.key_id === "string" && e.key_id !== `key_${fingerprint.slice(0, 24)}`) {
            fail("key_registry", `El key_id de ${e.key_id} no deriva de su huella`);
            registryOk = false;
        }
        const core = {
            format: "MT-KEY-REGISTRATION-1",
            tenant_ref: e.tenant_ref, public_key: e.public_key,
            purpose: e.purpose, key_fingerprint: fingerprint,
        };
        let statementDigest = null;
        try {
            statementDigest = attHMt("MT:KEY-REGISTRATION:V1", canonicalBytes(core));
        }
        catch {
            statementDigest = null;
        }
        if (statementDigest === null || e.registration_statement_digest !== statementDigest) {
            fail("key_registry", `La huella de la declaración de registro de ${e.key_id} no reproduce`);
            registryOk = false;
        }
        const pop = attB64Url(e.pop_signature_b64u);
        let popOk = false;
        if (pop !== null && pop.length === 4627 && statementDigest !== null) {
            try {
                popOk = verifyMlDsa87(e.public_key, canonicalBytes(core), pop);
            }
            catch {
                popOk = false;
            }
        }
        if (!popOk) {
            fail("key_registry", `La prueba de posesión de la clave ${e.key_id} no verifica (§13.3)`);
            registryOk = false;
        }
        registry.set(e.key_id, e);
    });
    if (registryOk && !components.all.some((c) => c.name === "key_registry" && c.status === "FAIL")) {
        components.set("key_registry", "OK");
    }
    // --- Conjunto de firmas: forma, pertenencia, propósitos y firmas ---
    const sigSet = sigSetRaw;
    let signerSetDigest = null;
    const distinctPubs = new Set();
    const rolesPresent = new Set();
    let signaturesAllValid = false;
    {
        const errs = [];
        const unknown = attUnknownField(sigSet, ["format", "record_id", "manifest_digest", "signatures"]);
        if (unknown !== null)
            errs.push(`MT-SIGNATURE-SET-1: campo no permitido «${unknown}»`);
        if (sigSet.format !== "MT-SIGNATURE-SET-1")
            errs.push("format debe ser MT-SIGNATURE-SET-1");
        if (sigSet.record_id !== manifest.record_id || sigSet.record_id !== pkg.record_id)
            errs.push("signature_set.record_id no coincide con el manifiesto ni con el paquete");
        if (manifestDigest === null || sigSet.manifest_digest !== manifestDigest)
            errs.push("signature_set.manifest_digest no coincide con la huella recalculada del manifiesto");
        const sigs = sigSet.signatures;
        if (!Array.isArray(sigs) || sigs.length < 1 || sigs.length > 8) {
            errs.push("signatures debe ser un array de 1..8 firmas");
        }
        else {
            const seenKeys = new Set();
            for (const sigRaw of sigs) {
                if (!isObj(sigRaw)) {
                    errs.push("Cada firma debe ser un objeto");
                    continue;
                }
                const u = attUnknownField(sigRaw, ATT_SIGNATURE_FIELDS);
                if (u !== null) {
                    errs.push(`firma: campo no permitido «${u}»`);
                    continue;
                }
                const s = sigRaw;
                if (typeof s.signer_key_id !== "string" || seenKeys.has(s.signer_key_id)) {
                    errs.push(`Clave firmante duplicada o inválida: ${JSON.stringify(s.signer_key_id)}`);
                    continue;
                }
                seenKeys.add(s.signer_key_id);
                if (s.role !== "TENANT_OWNER" && s.role !== "TENANT_ATTESTER") {
                    errs.push(`Rol no admitido: ${JSON.stringify(s.role)}`);
                    continue;
                }
                if (s.context !== ATT_ROLE_CONTEXT[s.role]) {
                    errs.push(`El contexto de ${s.role} debe ser ${ATT_ROLE_CONTEXT[s.role]}`);
                    continue;
                }
                if (!attIsIso(s.signed_at)) {
                    errs.push("signed_at debe ser ISO-8601 UTC");
                    continue;
                }
                const key = registry.get(s.signer_key_id);
                if (!key) {
                    errs.push(`Clave firmante ausente de la instantánea del registro: ${s.signer_key_id}`);
                    continue;
                }
                if (key.status !== "ACTIVE") {
                    errs.push(`La clave ${s.signer_key_id} no figura ACTIVE en la instantánea (${String(key.status)})`);
                    continue;
                }
                if (key.purpose !== ATT_ROLE_PURPOSE[s.role]) {
                    errs.push(`La clave ${s.signer_key_id} tiene propósito ${String(key.purpose)} y no puede firmar con rol ${String(s.role)}`);
                    continue;
                }
                if (distinctPubs.has(key.public_key)) {
                    errs.push("Dos entradas firman con la misma clave pública");
                    continue;
                }
                const sigBytes = attB64Url(s.signature_b64u);
                if (sigBytes === null || sigBytes.length !== 4627) {
                    errs.push(`La firma de ${s.signer_key_id} no es base64url estricto de 4627 bytes`);
                    continue;
                }
                let ok = false;
                try {
                    ok = manifestDigest !== null && verifyMlDsa87(key.public_key, attSigningMessage(ATTESTATION_CHAIN_ID, s.context, manifestDigest), sigBytes);
                }
                catch {
                    ok = false;
                }
                if (!ok) {
                    errs.push(`La firma de ${s.signer_key_id} NO verifica sobre el manifiesto`);
                    continue;
                }
                distinctPubs.add(key.public_key);
                rolesPresent.add(s.role);
            }
            signaturesAllValid = errs.length === 0;
        }
        try {
            signerSetDigest = attHMt("MT:SIGNER-SET:V1", canonicalBytes(sigSet));
        }
        catch {
            signerSetDigest = null;
        }
        if (errs.length > 0)
            fail("signature_set", errs.join("; "));
        else
            components.set("signature_set", "OK");
    }
    // --- Artefacto: coherencia con el manifiesto y huella de los bytes ---
    let artifactBytes = null;
    {
        const errs = [];
        if (artifact.artifact_id !== manifest.artifact_id)
            errs.push("artifact.artifact_id no coincide con el manifiesto");
        if (artifact.confidentiality !== manifest.confidentiality)
            errs.push("artifact.confidentiality no coincide con el manifiesto");
        if (artifact.media_type !== manifest.artifact_media_type)
            errs.push("artifact.media_type no coincide con el manifiesto");
        if (artifact.byte_length !== manifest.byte_length)
            errs.push("artifact.byte_length no coincide con el manifiesto");
        if (artifact.content_b64u !== undefined) {
            const bytes = attB64Url(artifact.content_b64u);
            if (bytes === null)
                errs.push("artifact.content_b64u no es base64url estricto");
            else
                artifactBytes = bytes;
        }
        if (errs.length > 0) {
            fail("artifact_digest", errs.join("; "));
        }
        else if (artifactBytes !== null) {
            if (attHMt("MT:ARTIFACT:V1", artifactBytes) !== manifest.artifact_digest) {
                fail("artifact_digest", "La huella H_MT(MT:ARTIFACT:V1) de los bytes del paquete NO coincide con artifact_digest del manifiesto");
            }
            else if (artifactBytes.length !== manifest.byte_length) {
                fail("artifact_digest", "La longitud de los bytes no coincide con byte_length del manifiesto");
            }
            else {
                components.set("artifact_digest", "OK");
            }
        }
        else if (manifest.confidentiality === "PUBLIC") {
            missing("artifact_digest", "El manifiesto declara un artefacto PUBLIC pero el paquete no incluye sus bytes: HASH_MATCH no es acreditable");
        }
        else {
            components.set("artifact_digest", "SKIPPED", "Artefacto PRIVATE: el paquete no incluye bytes (nunca salen del cliente); solo viaja la huella comprometida, cuya coherencia juzgan package_integrity y record_commitment");
        }
    }
    // --- Huella del paquete y compromiso del registro (§5.2.1) ---
    let packageDigest = null;
    if (manifestDigest !== null && claimsCommitment !== null && signerSetDigest !== null && attIsDigest(manifest.artifact_digest)) {
        try {
            packageDigest = attHMt("MT:PACKAGE:V1", canonicalBytes({
                manifest_digest: manifestDigest,
                claims_commitment: claimsCommitment,
                artifact_digest: manifest.artifact_digest,
                signer_set_digest: signerSetDigest,
            }));
        }
        catch {
            packageDigest = null;
        }
    }
    if (packageDigest === null || pkg.package_digest !== packageDigest) {
        fail("package_integrity", "La huella del paquete recalculada (MT:PACKAGE:V1) NO coincide con la declarada");
    }
    else {
        components.set("package_integrity", "OK");
    }
    let recordCommitment = null;
    if (packageDigest !== null && Number.isSafeInteger(evidence.client_sequence)) {
        try {
            recordCommitment = attHMt("MT:RECORD:V1", canonicalBytes({
                tenant_ref: manifest.tenant_ref,
                record_id: manifest.record_id,
                manifest_digest: manifestDigest,
                package_digest: packageDigest,
                client_sequence: evidence.client_sequence,
            }));
        }
        catch {
            recordCommitment = null;
        }
    }
    if (recordCommitment === null || evidence.record_commitment !== recordCommitment) {
        fail("record_commitment", "El compromiso del registro recalculado (MT:RECORD:V1) NO coincide con el declarado en la sección de evidencia");
    }
    else {
        components.set("record_commitment", "OK");
    }
    // --- Checkpoint y su QC ---
    const checkpointRaw = evidence.checkpoint;
    const qcRaw = evidence.checkpoint_qc;
    let checkpoint = null;
    let checkpointDigest = null;
    if (checkpointRaw === null || checkpointRaw === undefined) {
        missing("checkpoint", "El paquete no trae checkpoint: el registro está aceptado en el registro de evidencias pero aún no certificado (la historia D04 exige el checkpoint para el veredicto completo)");
        components.set("checkpoint_finality", "SKIPPED", "Sin checkpoint no hay QC que juzgar");
        components.set("checkpoint_archive", "SKIPPED", "Sin checkpoint no hay firma de archivo que juzgar");
        missing("evidence_inclusion", "Sin checkpoint no hay raíz contra la que juzgar la inclusión");
    }
    else if (!isObj(checkpointRaw)) {
        fail("checkpoint", "La sección checkpoint no es un objeto");
    }
    else {
        checkpoint = checkpointRaw;
        const unknown = attUnknownField(checkpoint, ATT_CHECKPOINT_FIELDS);
        if (unknown !== null)
            fail("checkpoint", `MT-CHECKPOINT-1: campo no permitido «${unknown}» (esquema cerrado)`);
        if (checkpoint.checkpoint_version !== "MT-CHECKPOINT-1")
            fail("checkpoint", "checkpoint_version debe ser MT-CHECKPOINT-1");
        if (checkpoint.network_id !== "testnet" || checkpoint.chain_id !== ATTESTATION_CHAIN_ID)
            fail("checkpoint", "El checkpoint no es de la testnet de este paquete");
        if (!Number.isSafeInteger(checkpoint.checkpoint_seq) || checkpoint.checkpoint_seq < 1)
            fail("checkpoint", "checkpoint_seq debe ser un entero ≥ 1");
        if (!Number.isSafeInteger(checkpoint.evidence_tree_size) || checkpoint.evidence_tree_size < 1)
            fail("checkpoint", "evidence_tree_size debe ser un entero ≥ 1");
        if (!attIsDigest(checkpoint.evidence_tree_root))
            fail("checkpoint", "evidence_tree_root debe ser una huella de 256 hex");
        if (!attIsDigest(checkpoint.previous_checkpoint_digest))
            fail("checkpoint", "previous_checkpoint_digest debe ser una huella de 256 hex");
        if (!Number.isSafeInteger(checkpoint.tip_block_height) || checkpoint.tip_block_height < 0)
            fail("checkpoint", "tip_block_height inválido");
        if (!attIsDigest(checkpoint.tip_block_hash))
            fail("checkpoint", "tip_block_hash debe ser una huella de 256 hex");
        if (!attIsDigest(checkpoint.validator_set_id))
            fail("checkpoint", "validator_set_id debe ser H del manifiesto canónico vigente (256 hex)");
        if (!attIsIso(checkpoint.created_at))
            fail("checkpoint", "created_at del checkpoint debe ser ISO-8601 UTC");
        try {
            checkpointDigest = attHMt("MT:CHECKPOINT-EVIDENCE:V1", canonicalBytes(checkpoint));
        }
        catch {
            checkpointDigest = null;
        }
        if (checkpointDigest === null) {
            fail("checkpoint", "El checkpoint no se puede canonicalizar para recomputar su huella");
        }
        else if (!components.all.some((c) => c.name === "checkpoint" && c.status === "FAIL")) {
            components.set("checkpoint", "OK");
        }
        // Inclusión del registro en el árbol sellado por el checkpoint.
        const inclusionErr = recordCommitment === null
            ? "Sin compromiso recalculado no se puede juzgar la inclusión"
            : attVerifyInclusion(recordCommitment, evidence.inclusion_proof, checkpoint.evidence_tree_root);
        if (inclusionErr !== null) {
            fail("evidence_inclusion", inclusionErr);
        }
        else {
            const proof = evidence.inclusion_proof;
            if (proof.tree_size !== checkpoint.evidence_tree_size || proof.leaf_index !== evidence.leaf_index) {
                fail("evidence_inclusion", "La prueba de inclusión no declara el tamaño del checkpoint ni el leaf_index de la sección de evidencia");
            }
            else {
                components.set("evidence_inclusion", "OK");
            }
        }
    }
    // --- Evidencia de cadena: génesis, manifiesto plano, cadena de
    // manifiestos, bloques y punta ligada al checkpoint ---
    const genesis = chainEv.genesis;
    const blocks = chainEv.blocks;
    const flatManifest = chainEv.validator_manifest;
    const sectionRaw = chainEv.manifest_chain;
    const gp = genesis.payload;
    if (genesis.block_number !== 0 || genesis.brick_number !== null ||
        genesis.prev_hash !== ZERO_HASH_1024 || gp.schema !== "MT-GENESIS-1" ||
        gp.chain_id !== ATTESTATION_CHAIN_ID || gp.network !== "testnet" || gp.supply !== 0) {
        fail("genesis", "El bloque génesis de la evidencia no tiene la forma esperada (bloque 0, testnet, suministro 0)");
    }
    else {
        components.set("genesis", "OK");
    }
    const fingerprint = pkg.constitution_fingerprint;
    if (!attIsDigest(fingerprint)) {
        missing("constitution_anchor", "El paquete no trae una huella constitucional MT-DUAL-1024");
    }
    else if (gp.constitution_fingerprint !== fingerprint) {
        fail("constitution_anchor", "La huella constitucional del paquete no coincide con la anclada en el génesis");
    }
    else {
        components.set("constitution_anchor", "OK");
    }
    if (!isObj(flatManifest) || !Array.isArray(flatManifest.validators)) {
        fail("validator_manifest", "La evidencia no trae un manifiesto plano de validadores utilizable");
    }
    else {
        const m = flatManifest;
        if (m.format !== "MT-VALIDATOR-MANIFEST-1")
            fail("validator_manifest", "El manifiesto plano no es un MT-VALIDATOR-MANIFEST-1");
        const mExtra = firstUnknownField(m, VALIDATOR_MANIFEST_FIELDS);
        if (mExtra !== null)
            fail("validator_manifest", schemaFieldNotAllowedMessage("el manifiesto de validadores del paquete", mExtra));
        const seenIds = new Set();
        for (const ve of m.validators) {
            if (isObj(ve) && typeof ve.validator_id === "string") {
                if (seenIds.has(ve.validator_id))
                    fail("validator_manifest", `validator_id duplicado en el manifiesto: ${ve.validator_id}`);
                seenIds.add(ve.validator_id);
            }
        }
        if (m.chain_id !== ATTESTATION_CHAIN_ID)
            fail("validator_manifest", "El manifiesto plano es de otra cadena");
        else if (m.quorum !== 3 || m.validators.length !== 4)
            fail("validator_manifest", `El manifiesto no declara 4 validadores con quórum 3 (quórum=${m.quorum}, n=${m.validators.length})`);
        if (!components.all.some((c) => c.name === "validator_manifest" && c.status === "FAIL")) {
            components.set("validator_manifest", "OK");
        }
    }
    const chainJudgment = judgeManifestChain(sectionRaw, { chainId: ATTESTATION_CHAIN_ID, genesisHash: genesis.block_hash });
    let flatCrossFailed = false;
    if (chainJudgment.errors.length > 0) {
        fail("validator_manifest_chain", chainJudgment.errors.join("; "));
    }
    else {
        components.set("validator_manifest_chain", "OK", "Cadena de manifiestos íntegra: bootstrap coherente, encadenamiento sin huecos, posesión y autorización de cada transición verificadas");
        if (isObj(flatManifest) && chainJudgment.current && !flatMatchesChained(flatManifest, chainJudgment.current)) {
            flatCrossFailed = true;
            fail("validator_manifest", `${MANIFEST_CHAIN_MISMATCH}: el manifiesto presentado no coincide con el manifiesto vigente de la cadena de manifiestos del paquete (H del vigente: ${chainJudgment.currentHash})`);
        }
    }
    const validatorPublicKey = typeof gp.validator_public_key === "string" ? gp.validator_public_key : undefined;
    if (!validatorPublicKey)
        missing("validator_signatures", "El génesis no declara la clave del validador firmante");
    const allBlocks = [genesis, ...blocks];
    {
        let expectedBrick = 1;
        for (let i = 0; i < allBlocks.length; i++) {
            const block = allBlocks[i];
            if (block.block_number !== i)
                fail("block_linkage", `El bloque en posición ${i} declara block_number=${block.block_number}`);
            if (i > 0 && block.prev_hash !== allBlocks[i - 1].block_hash)
                fail("block_linkage", `El bloque ${i} no encadena con el anterior (prev_hash distinto)`);
            let recomputed;
            try {
                recomputed = mtDual1024(blockCoreBytes(block), BLOCK_HASH_DOMAIN);
            }
            catch {
                recomputed = undefined;
            }
            if (recomputed === undefined)
                fail("block_fingerprints", `El bloque ${i} no se puede canonicalizar`);
            else if (recomputed !== block.block_hash)
                fail("block_fingerprints", `La huella MT-DUAL-1024 del bloque ${i} no coincide (contenido alterado)`);
            if (validatorPublicKey) {
                let sigOk = false;
                try {
                    sigOk = verifyMlDsa87(validatorPublicKey, blockCoreBytes(block), Buffer.from(block.validator_signature ?? "", "base64"));
                }
                catch {
                    sigOk = false;
                }
                if (!sigOk)
                    fail("validator_signatures", `La firma ML-DSA-87 del bloque ${i} no verifica`);
            }
            if (!block.finality) {
                fail("finality_certificates", `El bloque ${i} no trae certificado de finalidad`);
            }
            else {
                const expected = blockTransition(block, ATTESTATION_CHAIN_ID);
                const certRaw = block.finality;
                if (isV2CertificateShape(certRaw)) {
                    if (chainJudgment.errors.length > 0) {
                        fail("finality_certificates", `El bloque ${i} trae un certificado MT-FINALITY-CERTIFICATE-2 pero la cadena de manifiestos del paquete no verifica`);
                    }
                    else {
                        const inForce = chainJudgment.manifestAtHeight(block.block_number);
                        if (!inForce)
                            fail("finality_certificates", `El bloque ${i} no tiene manifiesto en vigor en la cadena presentada`);
                        else {
                            const vErrs = judgeV2Certificate(inForce, certRaw, expected);
                            if (vErrs.length > 0)
                                fail("finality_certificates", `El certificado v2 del bloque ${i} no verifica: ${vErrs.join("; ")}`);
                        }
                    }
                }
                else {
                    if (canonicalize(block.finality.transition) !== canonicalize(expected)) {
                        fail("finality_certificates", `El certificado del bloque ${i} no corresponde a su transición`);
                    }
                    const activation = chainJudgment.errors.length === 0 ? chainJudgment.bootstrap?.finality_activation_height : undefined;
                    if (activation !== undefined && block.block_number >= activation) {
                        fail("finality_certificates", `El bloque ${i} trae un certificado v1 en la altura ${block.block_number}, tras la activación v2 (${activation}): se exige MT-FINALITY-CERTIFICATE-2`);
                    }
                    const inForce = chainJudgment.errors.length === 0 ? chainJudgment.manifestAtHeight(block.block_number) : undefined;
                    const effectiveManifest = inForce ? operationalManifest(inForce) : flatManifest;
                    const vc = judgeV1Certificate(effectiveManifest, block.finality);
                    if (!vc.valid)
                        fail("finality_certificates", `El certificado del bloque ${i} no alcanza o no verifica: ${vc.errors.join("; ")}`);
                }
            }
            if (i > 0) {
                if (block.brick_number !== expectedBrick)
                    fail("block_linkage", `Ladrillo ${block.brick_number} fuera de secuencia (se esperaba ${expectedBrick})`);
                expectedBrick++;
            }
        }
        if (!components.all.some((c) => c.name === "block_linkage" && c.status === "FAIL"))
            components.set("block_linkage", "OK");
        if (!components.all.some((c) => c.name === "block_fingerprints" && c.status === "FAIL"))
            components.set("block_fingerprints", "OK");
        if (validatorPublicKey && !components.all.some((c) => c.name === "validator_signatures" && c.status === "FAIL"))
            components.set("validator_signatures", "OK");
        if (!components.all.some((c) => c.name === "finality_certificates" && c.status === "FAIL"))
            components.set("finality_certificates", "OK");
    }
    const tip = allBlocks[allBlocks.length - 1];
    if (checkpoint) {
        if (tip.block_number !== checkpoint.tip_block_height || tip.block_hash !== checkpoint.tip_block_hash) {
            fail("chain_tip_binding", "La punta de la evidencia de cadena NO es el bloque ligado por el checkpoint (altura/hash distintos): el checkpoint no ancla esta cadena");
        }
        else {
            components.set("chain_tip_binding", "OK");
        }
    }
    else {
        components.set("chain_tip_binding", "SKIPPED", "Sin checkpoint no hay punta ligada que contrastar");
    }
    // --- QC del checkpoint: finalidad del comité + firma de archivo ---
    if (checkpoint && checkpointDigest !== null) {
        if (!isObj(qcRaw)) {
            fail("checkpoint_finality", "El paquete trae checkpoint pero no su QC (MT-CHECKPOINT-QC-1)");
            components.set("checkpoint_archive", "SKIPPED", "Sin QC no hay firma de archivo que juzgar");
        }
        else {
            const qc = qcRaw;
            if (qc.format !== "MT-CHECKPOINT-QC-1")
                fail("checkpoint_finality", "El QC no es un MT-CHECKPOINT-QC-1");
            if (qc.checkpoint_digest !== checkpointDigest)
                fail("checkpoint_finality", "El QC no declara la huella recalculada del checkpoint");
            if (qc.validator_set_id !== checkpoint.validator_set_id)
                fail("checkpoint_finality", "El QC no declara el mismo conjunto de validadores que el checkpoint");
            let qcDigest = null;
            try {
                qcDigest = attHMt("MT:CHECKPOINT-QC:V1", canonicalBytes(qc.finality_certificate));
            }
            catch {
                qcDigest = null;
            }
            if (qcDigest === null || qc.finality_certificate_digest !== qcDigest) {
                fail("checkpoint_finality", "La huella del certificado de finalidad del QC no reproduce");
            }
            const certRaw = qc.finality_certificate;
            if (!isObj(certRaw) || !isObj(certRaw.transition)) {
                fail("checkpoint_finality", "El QC no trae un certificado de finalidad con transición");
            }
            else {
                const expectedDescriptor = {
                    chain_id: ATTESTATION_CHAIN_ID,
                    kind: "MT-EVIDENCE-CHECKPOINT-1",
                    sequence: checkpoint.checkpoint_seq,
                    prev_state: checkpoint.previous_checkpoint_digest,
                    transition_hash: checkpointDigest,
                };
                if (canonicalize(certRaw.transition) !== canonicalize(expectedDescriptor)) {
                    fail("checkpoint_finality", "La transición del certificado del QC no es la transición del checkpoint (cadena, tipo MT-EVIDENCE-CHECKPOINT-1, secuencia, estado previo y huella deben coincidir)");
                }
                const idx = chainJudgment.hashes.indexOf(checkpoint.validator_set_id);
                if (chainJudgment.errors.length > 0) {
                    fail("checkpoint_finality", "La cadena de manifiestos no verifica: no hay conjunto contra el que juzgar el QC");
                }
                else if (idx < 0) {
                    fail("checkpoint_finality", "El validator_set_id del checkpoint no es ningún manifiesto de la cadena presentada: el QC no procede del conjunto anclado");
                }
                else {
                    const inForce = chainJudgment.manifests[idx];
                    const vc = judgeV1Certificate(operationalManifest(inForce), certRaw);
                    if (!vc.valid)
                        fail("checkpoint_finality", `El certificado del QC no alcanza el quórum o no verifica: ${vc.errors.join("; ")}`);
                    else if (!components.all.some((c) => c.name === "checkpoint_finality" && c.status === "FAIL")) {
                        components.set("checkpoint_finality", "OK", `Certificado de finalidad del checkpoint verificado contra el manifiesto anclado (${vc.distinct_signers} firmantes distintos)`);
                    }
                }
            }
            const arch = qc.archive_signature;
            if (!isObj(arch)) {
                fail("checkpoint_archive", "El QC no trae la firma de archivo SLH-DSA");
            }
            else {
                if (arch.algorithm !== "SLH-DSA-SHAKE-256s" || arch.context !== "MT-CHECKPOINT-ARCHIVE-V1") {
                    fail("checkpoint_archive", "La firma de archivo no declara SLH-DSA-SHAKE-256s / MT-CHECKPOINT-ARCHIVE-V1");
                }
                if (typeof arch.public_key !== "string" || !isSlhDsaShake256sPublicKey(arch.public_key)) {
                    fail("checkpoint_archive", "La clave pública de archivo no tiene la forma SLH-DSA-SHAKE-256s");
                }
                const sigBytes = attB64Url(arch.signature_b64u);
                if (sigBytes === null || sigBytes.length !== 29792) {
                    fail("checkpoint_archive", "La firma de archivo no es base64url estricto de 29792 bytes");
                }
                else {
                    const msg = Buffer.concat([
                        Buffer.from("MT-CHECKPOINT-ARCHIVE-V1", "utf8"), Buffer.from([0]),
                        Buffer.from(ATTESTATION_CHAIN_ID, "utf8"), Buffer.from([0]),
                        Buffer.from(checkpointDigest, "utf8"),
                    ]);
                    let ok = false;
                    try {
                        ok = verifySlhDsaShake256s(arch.public_key, msg, sigBytes);
                    }
                    catch {
                        ok = false;
                    }
                    if (!ok)
                        fail("checkpoint_archive", "La firma de archivo SLH-DSA NO verifica sobre la huella del checkpoint");
                    else if (!components.all.some((c) => c.name === "checkpoint_archive" && c.status === "FAIL")) {
                        components.set("checkpoint_archive", "OK");
                    }
                }
            }
        }
    }
    // --- Anclas externas (AUD-01 + F-A6-01 + F-ADV-02, espejo de la ruta de ladrillos) ---
    let initialAnchorMatched = false;
    let manifestAnchorFailed = false;
    const anyAnchor = anchors &&
        (anchors.constitution_fingerprint !== undefined ||
            anchors.genesis_block_hash !== undefined ||
            anchors.initial_validator_manifest_hash !== undefined ||
            anchors.current_validator_manifest_hash !== undefined ||
            anchors.bootstrap_hash !== undefined);
    if (anyAnchor) {
        let anchorFailed = false;
        if (anchors.constitution_fingerprint !== undefined && anchors.constitution_fingerprint !== fingerprint) {
            fail("external_anchor", "La huella constitucional del paquete NO coincide con el ancla externa esperada");
            anchorFailed = true;
        }
        if (anchors.genesis_block_hash !== undefined && anchors.genesis_block_hash !== genesis.block_hash) {
            fail("external_anchor", "El hash del bloque génesis del paquete NO coincide con el ancla externa esperada");
            anchorFailed = true;
        }
        if (anchors.initial_validator_manifest_hash !== undefined) {
            if (chainJudgment.errors.length > 0 || !chainJudgment.bootstrap) {
                fail("validator_manifest_anchor", `${MANIFEST_CHAIN_MISMATCH}: se aportó el ancla externa del manifiesto inicial pero la cadena de manifiestos del paquete no verifica`);
                anchorFailed = true;
                manifestAnchorFailed = true;
            }
            else if (anchors.initial_validator_manifest_hash !== chainJudgment.bootstrap.initial_manifest_hash) {
                fail("validator_manifest_anchor", `${MANIFEST_CHAIN_MISMATCH}: el bootstrap de la cadena presentada no es el bootstrap publicado (su initial_manifest_hash no coincide con el ancla externa)`);
                anchorFailed = true;
                manifestAnchorFailed = true;
            }
            else if (chainJudgment.hashes[0] !== anchors.initial_validator_manifest_hash) {
                fail("validator_manifest_anchor", `${MANIFEST_CHAIN_MISMATCH}: H(M0) calculado desde el manifiesto inicial del paquete no coincide con el ancla externa publicada`);
                anchorFailed = true;
                manifestAnchorFailed = true;
            }
            else {
                components.set("validator_manifest_anchor", "OK", "Contraste exacto de este componente: el initial_manifest_hash declarado en el bootstrap presentado coincide con el ancla externa aportada, y H(M0), calculado desde el manifiesto inicial del paquete, coincide con ambos");
                initialAnchorMatched = true;
            }
        }
        if (anchors.current_validator_manifest_hash !== undefined) {
            if (chainJudgment.errors.length > 0 || !chainJudgment.currentHash) {
                fail("current_manifest_anchor", `${MANIFEST_CHAIN_MISMATCH}: se aportó el ancla del manifiesto actual pero el paquete no trae una cadena de manifiestos válida`);
                anchorFailed = true;
                manifestAnchorFailed = true;
            }
            else if (chainJudgment.currentHash !== anchors.current_validator_manifest_hash) {
                fail("current_manifest_anchor", `${MANIFEST_CHAIN_MISMATCH}: H del manifiesto vigente no coincide con el ancla actual aportada`);
                anchorFailed = true;
                manifestAnchorFailed = true;
            }
            else {
                components.set("current_manifest_anchor", "OK", "El manifiesto vigente coincide con el ancla actual aportada");
            }
        }
        if (anchors.bootstrap_hash !== undefined) {
            // F-20-01 (espejo de las rutas de ladrillo y de manifiesto): el
            // ancla del bootstrap compromete el bootstrap ENTERO — también
            // finality_activation_height, que despacha la finalidad de los
            // bloques del checkpoint en esta ruta — contra H(bootstrap)
            // calculado del presentado.
            if (chainJudgment.errors.length > 0 || !chainJudgment.bootstrap) {
                fail("bootstrap_anchor", `${MANIFEST_CHAIN_MISMATCH}: se aportó el ancla externa del bootstrap pero la cadena de manifiestos del paquete no verifica o no trae bootstrap que contrastar`);
                anchorFailed = true;
                manifestAnchorFailed = true;
            }
            else if (bootstrapHash(chainJudgment.bootstrap) !== anchors.bootstrap_hash) {
                fail("bootstrap_anchor", `${MANIFEST_CHAIN_MISMATCH}: el bootstrap presentado no es el bootstrap publicado: H(bootstrap) no coincide con el ancla externa aportada. El hash del bootstrap compromete su contenido entero —también finality_activation_height, que H(M0) no cubre— (F-20-01)`);
                anchorFailed = true;
                manifestAnchorFailed = true;
            }
            else {
                components.set("bootstrap_anchor", "OK", "H(bootstrap) calculado desde el bootstrap presentado coincide con el ancla externa aportada: el contenido entero del bootstrap —incluida finality_activation_height— es el publicado");
            }
        }
        if (anchorFailed) {
            fail("external_anchor", "Al menos una de las anclas externas aportadas NO coincide con el paquete (ver el componente específico)");
        }
        else {
            components.set("external_anchor", "OK", "El paquete coincide con todas las anclas externas aportadas (huella constitucional, hash del génesis y/o anclas de manifiesto)");
        }
    }
    else {
        components.set("external_anchor", "SKIPPED", "SIN ANCLA EXTERNA: este veredicto prueba la consistencia INTERNA del paquete, no su autenticidad contra la cadena real (AUD-01). Aportar constitution_fingerprint, genesis_block_hash, initial_validator_manifest_hash y bootstrap_hash publicados fuera del paquete permite contrastar la constitución, el génesis, la raíz de la cadena de manifiestos y el bootstrap entero contra lo publicado.");
    }
    if (chainJudgment.errors.length === 0 && anchors?.initial_validator_manifest_hash === undefined) {
        components.set("validator_manifest_anchor", "SKIPPED", "La cadena de manifiestos es íntegra por dentro, pero su raíz H(M0) no se contrastó contra ningún valor externo: aporta initial_validator_manifest_hash del bootstrap publicado para anclar la atribución");
    }
    if (chainJudgment.errors.length === 0 && chainJudgment.bootstrap && anchors?.bootstrap_hash === undefined) {
        components.set("bootstrap_anchor", "SKIPPED", "La cadena de manifiestos es íntegra por dentro, pero el hash del bootstrap H(bootstrap) no se contrastó contra ningún valor externo: sin esa ancla, finality_activation_height y el resto del contenido del bootstrap quedan acreditados solo por la consistencia interna (F-20-01). Aporta bootstrap_hash del bootstrap publicado para anclarlos");
    }
    // --- Atribución (espejo de la ruta de ladrillos) ---
    let attribution;
    if (manifestAnchorFailed) {
        components.set("validator_attribution", "FAIL", "Se aportó un ancla de manifiesto y el juicio la contradice: la atribución de finalidad queda rechazada");
        attribution = { status: "INVALID", from_height: chainJudgment.bootstrap?.bootstrap_height ?? 0, detail: "El ancla de manifiesto aportada contradice la cadena presentada: atribución rechazada" };
    }
    else if (chainJudgment.errors.length > 0) {
        components.set("validator_attribution", "FAIL", "La cadena de manifiestos no verifica: la atribución de finalidad queda rechazada");
        attribution = { status: "INVALID", from_height: chainJudgment.bootstrap?.bootstrap_height ?? 0, detail: "La cadena de manifiestos presentada no verifica" };
    }
    else if (flatCrossFailed) {
        components.set("validator_attribution", "FAIL", "El manifiesto presentado contradice el manifiesto vigente de su propia cadena anclada: la atribución queda rechazada");
        attribution = { status: "INVALID", from_height: chainJudgment.bootstrap?.bootstrap_height ?? 0, detail: "El manifiesto del paquete no es el manifiesto vigente de la cadena anclada que el propio paquete presenta" };
    }
    else {
        const fromHeight = chainJudgment.bootstrap?.bootstrap_height ?? 0;
        if (fromHeight > 0) {
            components.set("validator_attribution", initialAnchorMatched ? "OK" : "SKIPPED", `PARTIAL FROM_HEIGHT ${fromHeight}: el bootstrap acredita la cadena solo desde la altura ${fromHeight}; la integridad anterior se verifica, la atribución no`);
            attribution = { status: "PARTIAL", from_height: fromHeight, detail: `La cadena acredita la atribución solo desde la altura ${fromHeight} (bootstrap de corte)` };
        }
        else if (initialAnchorMatched) {
            components.set("validator_attribution", "OK", "Atribución anclada: H(M0) contrastada contra el ancla externa y cadena íntegra hasta el manifiesto vigente");
            attribution = { status: "ANCHORED", from_height: 0, detail: "Atribución anclada contra el ancla externa del manifiesto inicial" };
        }
        else {
            components.set("validator_attribution", "SKIPPED", "Cadena de manifiestos íntegra y encadenada, pero su raíz no se contrastó contra un valor externo: la integridad está probada, la atribución no");
            attribution = { status: "UNANCHORED", from_height: 0, detail: "Cadena íntegra por dentro, raíz no contrastada contra un valor externo" };
        }
    }
    // --- Rastro de auditoría del registro (cadena por registro, §7.3) ---
    {
        const trail = auditRaw;
        const errs = [];
        let prev = ZERO_HASH_1024;
        let prevTime = "";
        const types = [];
        const knowable = {
            RECORD_SCHEMA_VALIDATED: manifestDigest,
            RECORD_COMMITMENT_VERIFIED: packageDigest,
            RECORD_ANCHOR_ACCEPTED: recordCommitment,
            RECORD_INCLUSION_PROOF_AVAILABLE: recordCommitment,
            RECORD_BLOCK_FINALIZED: checkpointDigest,
            RECORD_CHECKPOINT_CERTIFIED: checkpointDigest,
            RECORD_EXPORTED: packageDigest,
        };
        trail.forEach((evRaw, i) => {
            if (!isObj(evRaw)) {
                errs.push(`El evento ${i} del rastro no es un objeto`);
                return;
            }
            const u = attUnknownField(evRaw, ATT_AUDIT_FIELDS);
            if (u !== null) {
                errs.push(`El evento ${i} trae el campo no permitido «${u}»`);
                return;
            }
            const ev = evRaw;
            if (ev.record_event_index !== i)
                errs.push(`El evento ${i} declara record_event_index=${JSON.stringify(ev.record_event_index)}`);
            if (ev.previous_record_event_digest !== prev)
                errs.push(`El evento ${i} no encadena con el anterior del registro`);
            if (!attIsIso(ev.occurred_at))
                errs.push(`El evento ${i} no declara un instante ISO-8601 UTC`);
            else {
                if (prevTime && ev.occurred_at < prevTime)
                    errs.push(`El evento ${i} es anterior al evento previo del rastro`);
                prevTime = ev.occurred_at;
            }
            let digest = null;
            try {
                digest = attHMt("MT:EVIDENCE-RECORD-EVENT:V1", canonicalBytes({
                    record_id: manifest.record_id, event_type: ev.event_type, occurred_at: ev.occurred_at,
                    payload_digest: ev.payload_digest, previous_record_event_digest: prev,
                }));
            }
            catch {
                digest = null;
            }
            if (digest === null || ev.record_event_digest !== digest)
                errs.push(`La huella del evento ${i} (${String(ev.event_type)}) no reproduce`);
            else
                prev = digest;
            if (typeof ev.event_type === "string")
                types.push(ev.event_type);
            const expectedPayload = knowable[ev.event_type];
            if (expectedPayload !== undefined && expectedPayload !== null) {
                const pd = attHMt("MT:EVIDENCE-EVENT-PAYLOAD:V1", expectedPayload);
                if (ev.payload_digest !== pd)
                    errs.push(`El evento ${i} (${String(ev.event_type)}) no compromete la huella esperada de su etapa`);
            }
        });
        const mandatory = ["RECORD_RECEIVED", "RECORD_SCHEMA_VALIDATED", "RECORD_COMMITMENT_VERIFIED", "RECORD_ANCHOR_ACCEPTED"];
        let cursor = -1;
        for (const t of mandatory) {
            const at = types.indexOf(t, cursor + 1);
            if (at < 0) {
                errs.push(`Falta el evento obligatorio ${t} en el rastro (o está fuera de orden)`);
                break;
            }
            cursor = at;
        }
        if (types.includes("RECORD_REJECTED"))
            errs.push("El rastro contiene RECORD_REJECTED: el registro fue rechazado y su paquete no debería existir");
        if (checkpoint) {
            let c2 = cursor;
            for (const t of ["RECORD_BLOCK_FINALIZED", "RECORD_INCLUSION_PROOF_AVAILABLE", "RECORD_CHECKPOINT_CERTIFIED"]) {
                const at = types.indexOf(t, c2 + 1);
                if (at < 0) {
                    errs.push(`El paquete trae checkpoint pero falta el evento ${t} en el rastro (o está fuera de orden)`);
                    break;
                }
                c2 = at;
            }
        }
        if (errs.length > 0)
            fail("audit_trail", errs.join("; "));
        else
            components.set("audit_trail", "OK", `Rastro íntegro: ${trail.length} eventos encadenados por huella, en el orden de la máquina de estados §7.2`);
    }
    // --- Predicados (resultados estructurados, nunca un genérico) ---
    const claimed = claimsJudgment.claimed;
    const compStatus = (name) => components.all.find((c) => c.name === name)?.status;
    // SCHEMA_VALID
    if (!claimed.has("SCHEMA_VALID"))
        setPredicate("SCHEMA_VALID", "NOT_CHECKED", "No reclamado en la atestación");
    else if (compStatus("manifest_schema") === "OK" && compStatus("manifest_canonical") === "OK" && compStatus("claims") === "OK") {
        setPredicate("SCHEMA_VALID", "PASS", "Esquema cerrado válido, forma canónica JCS reproducida byte a byte y compromiso de claims íntegro");
    }
    else
        setPredicate("SCHEMA_VALID", "FAIL", "El manifiesto o las claims no cumplen el esquema cerrado o su forma canónica");
    // HASH_MATCH / FILE_SIZE
    for (const id of ["HASH_MATCH", "FILE_SIZE"]) {
        if (!claimed.has(id)) {
            setPredicate(id, "NOT_CHECKED", "No reclamado en la atestación");
            continue;
        }
        if (artifactBytes === null) {
            setPredicate(id, "NOT_CHECKED", "El paquete no incluye los bytes del artefacto (confidencialidad PRIVATE): el predicado no es comprobable offline");
            continue;
        }
        if (id === "HASH_MATCH") {
            const ok = attHMt("MT:ARTIFACT:V1", artifactBytes) === manifest.artifact_digest;
            setPredicate(id, ok ? "PASS" : "FAIL", ok ? "La huella recalculada de los bytes coincide con la comprometida" : "La huella recalculada NO coincide con la comprometida");
        }
        else {
            const ok = artifactBytes.length === manifest.byte_length;
            setPredicate(id, ok ? "PASS" : "FAIL", ok ? "La longitud coincide con la declarada" : `Longitud real ${artifactBytes.length} ≠ declarada ${String(manifest.byte_length)}`);
        }
    }
    // MULTI_SIG
    if (!claimed.has("MULTI_SIG"))
        setPredicate("MULTI_SIG", "NOT_CHECKED", "No reclamado en la atestación");
    else {
        const params = claimed.get("MULTI_SIG");
        if (!signaturesAllValid || compStatus("signature_set") !== "OK") {
            setPredicate("MULTI_SIG", "FAIL", "El conjunto de firmas no verifica en su totalidad contra el registro de claves del paquete");
        }
        else if (distinctPubs.size < params.min_signatures) {
            setPredicate("MULTI_SIG", "FAIL", `Solo ${distinctPubs.size} claves distintas firmaron: se reclaman ${params.min_signatures}`);
        }
        else if (!params.required_roles.every((r) => rolesPresent.has(r))) {
            setPredicate("MULTI_SIG", "FAIL", "Falta algún rol exigido entre los firmantes");
        }
        else {
            setPredicate("MULTI_SIG", "PASS", `${distinctPubs.size} claves distintas registradas firmaron el manifiesto en los roles exigidos`);
        }
    }
    // TIME_BOUND
    if (!claimed.has("TIME_BOUND"))
        setPredicate("TIME_BOUND", "NOT_CHECKED", "No reclamado en la atestación");
    else if (!checkpoint || compStatus("checkpoint") !== "OK") {
        setPredicate("TIME_BOUND", "NOT_CHECKED", "Sin checkpoint certificado íntegro no hay cota temporal anclada que juzgar");
    }
    else {
        const params = claimed.get("TIME_BOUND");
        const created = manifest.created_at;
        if (created < params.not_before || created > params.not_after) {
            setPredicate("TIME_BOUND", "FAIL", "El instante declarado de la atestación cae fuera de las cotas reclamadas");
        }
        else if (checkpoint.created_at < created) {
            setPredicate("TIME_BOUND", "FAIL", "El checkpoint es anterior al instante declarado: la cota no está anclada");
        }
        else {
            setPredicate("TIME_BOUND", "PASS", "La atestación existía en el checkpoint certificado y su instante cae dentro de las cotas reclamadas. Sin TSA externa no acredita marca temporal independiente (RFC 3161)");
        }
    }
    // Sello temporal §9 (tranche C2-2): si el paquete trae timestamp_token, se
    // juzga como componente y TIME_BOUND declara INDEPENDENT_TIMESTAMP_VERIFIED
    // solo con sello válido sobre package_digest.
    const tsJudged = attJudgeTimestampToken(pkg);
    if (tsJudged !== null) {
        if (tsJudged.ok)
            components.set("timestamp_token", "OK", tsJudged.detail);
        else
            fail("timestamp_token", tsJudged.detail);
        if (claimed.has("TIME_BOUND")) {
            if (!tsJudged.ok)
                setPredicate("TIME_BOUND", "FAIL", tsJudged.detail);
            else if (predicates.TIME_BOUND?.status === "PASS")
                setPredicate("TIME_BOUND", "PASS", `${predicates.TIME_BOUND.detail ?? ""} ${tsJudged.detail}`);
        }
    }
    // TEST_SUITE_PASS (E25 cableado, tranche C2-2): se evalúa contra la sección
    // MT-DELIVERY-EVIDENCE-1 del paquete; sin ella no se afirma.
    if (!claimed.has("TEST_SUITE_PASS")) {
        setPredicate("TEST_SUITE_PASS", "NOT_CHECKED", "No reclamado en la atestación");
    }
    else if (pkg.delivery_evidence === undefined) {
        setPredicate("TEST_SUITE_PASS", "NOT_CHECKED", "El paquete no trae MT-DELIVERY-EVIDENCE-1 (E25): no se afirma");
    }
    else {
        const params = claimed.get("TEST_SUITE_PASS");
        const judged = attJudgeDeliverySection(pkg.delivery_evidence, manifest.tenant_ref, params.report_digest);
        setPredicate("TEST_SUITE_PASS", judged.status, judged.detail);
    }
    const anyPredicateFail = Object.values(predicates).some((p) => p.status === "FAIL");
    const verdict = components.hasFail() || anyPredicateFail ? "INVALID" : components.hasMissing() ? "INCOMPLETE" : "VALID";
    return {
        verdict,
        ...(typeof pkg.record_id === "string" ? { record_id: pkg.record_id } : {}),
        height: tip.block_number,
        components: components.all,
        errors,
        ...(attribution ? { attribution } : {}),
        predicates,
    };
}
