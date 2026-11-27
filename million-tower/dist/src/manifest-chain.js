/**
 * MT-VALIDATOR-MANIFEST-CHAIN-1 — cadena de manifiestos de validadores
 * anclada (cierre estructural del defecto F-A6-01, hallazgo ALTA de la
 * revisión independiente A6: el manifiesto de validadores de mt-verify
 * era autodeclarado y sustituible por completo, incluso con las anclas
 * externas en OK — caso G2).
 *
 * Mecanismo adoptado por adjudicación de la casa (2026-11-06) sobre los
 * fallos convergentes de GPT (Extra High) y DeepSeek (DeepThink):
 * composición (b)+(a) — la huella del manifiesto inicial H(M0) se
 * compromete en el génesis de producción (cubierta por la huella del
 * génesis anclada externamente) o, en la testnet ya existente, se
 * publica en el objeto externo MT-VALIDATOR-MANIFEST-BOOTSTRAP-1 junto
 * a las anclas actuales, SIN tocar su génesis ni su historia. Cada
 * sucesor Mi+1 entra encadenado: el bloque que lo introduce lo finaliza
 * el conjunto ANTIGUO (el nuevo no se autoproclama) mediante un
 * certificado de transición MT-VALIDATOR-SET-TRANSITION-1 firmado por
 * el quórum de supervivientes del conjunto saliente y, por ser toda
 * transición de conjunto una ceremonia E-19, también por la autoridad
 * fría SLH-DSA 2-de-3 (dos firmas INDEPENDIENTES de custodios
 * distintos; no existe ninguna «firma umbral SLH-DSA» aquí). Cada
 * certificado de finalidad v2 (MT-FINALITY-CERTIFICATE-2, activación
 * versionada) declara epoch y H(M_vigente) y firma un mensaje con
 * dominio MT-FINALITY-V1 que los vincula.
 *
 * Este módulo es el lado PRODUCTOR (cadena, exportadores y baterías):
 * tipos canónicos, políticas de red autenticadas, constructores y una
 * verificación completa reutilizable. mt-verify NO importa esta
 * verificación: reimplementa el juicio en src/mt-verify.ts compartiendo
 * solo tipos, constantes, listas de esquema (src/schema.ts) y
 * primitivas — la misma doctrina con la que ya comparte
 * verifyCertificate y src/schema.ts. La batería 18 cruza ambos juicios
 * sobre todos los casos (divergencia = fallo).
 *
 * Las listas concretas de campos las diseña el implementador desde los
 * requisitos enunciados en ambos fallos (las listas largas de GPT
 * llegaron truncadas en la extracción del navegador); se devuelven a
 * la casa en el informe de cierre para su aprobación. Ningún campo se
 * atribuye a GPT que no conste leído.
 *
 * Decisiones de diseño declaradas:
 *  - H(M) se calcula sobre el NÚCLEO del manifiesto: las pruebas de
 *    posesión (proof_of_possession) son evidencia ADJUNTA verificada
 *    contra H(M), no parte de la identidad hasheada (como la firma no
 *    forma parte del TBS de un certificado X.509). Así H(M) es estable
 *    aunque una PoP se regenere.
 *  - Presentación canónica de firmas: votos, firmas de supervivientes
 *    y firmas frías viajan ORDENADOS estrictamente por id; cualquier
 *    otro orden es INVALID (regla de forma canónica, no de conteo).
 *  - Toda transición de conjunto es una ceremonia E-19: exige
 *    autoridad fría asentada en la raíz. Una red sin autoridad fría
 *    asentada (la testnet actual: nunca sentó custodios) no admite
 *    transiciones; el bootstrap lo declara y cualquier transición
 *    presentada es INVALID.
 *  - El quórum y el tamaño del conjunto salen SIEMPRE de la política
 *    de red autenticada de este módulo (configuración del verificador
 *    y del productor), nunca de un campo del manifiesto presentado.
 *
 * TESTNET en lo que toca a data/: esto no crea génesis de producción
 * ni mueve dinero real (BLOQUEADO). E-17 intacta: producción N=7,
 * 5-de-7, f=2, sin stake — aquí solo como política declarada.
 */
import { canonicalBytes } from "./jcs.js";
import { mtDual1024, ZERO_HASH_1024 } from "./hash.js";
import { isMlDsa87PublicKey, isSlhDsaShake256sPublicKey, verifyMlDsa87, verifySlhDsaShake256s, } from "./keys.js";
import { firstUnknownField, schemaFieldNotAllowedMessage, CANONICAL_MANIFEST_ENTRY_FIELDS, CANONICAL_MANIFEST_FIELDS, COLD_AUTHORITY_FIELDS, COLD_CUSTODIAN_FIELDS, COLD_SIGNATURE_FIELDS, FINALITY_CERTIFICATE_V2_FIELDS, MANIFEST_BOOTSTRAP_FIELDS, MANIFEST_CHAIN_SECTION_FIELDS, SET_TRANSITION_FIELDS, SURVIVOR_SIGNATURE_FIELDS, VOTE_FIELDS, TRANSITION_DESCRIPTOR_FIELDS, } from "./schema.js";
import { ConsensusError, } from "./validators.js";
/* ------------------------------------------------------------------ */
/* Constantes de formato y dominios                                    */
/* ------------------------------------------------------------------ */
export const MANIFEST_FORMAT = "MT-VALIDATOR-MANIFEST-1";
export const MANIFEST_SCHEMA_VERSION = "1";
export const BOOTSTRAP_FORMAT = "MT-VALIDATOR-MANIFEST-BOOTSTRAP-1";
export const TRANSITION_FORMAT = "MT-VALIDATOR-SET-TRANSITION-1";
export const FINALITY_POLICY_FORMAT = "MT-FINALITY-POLICY-1";
export const TRANSITION_POLICY_FORMAT = "MT-TRANSITION-POLICY-1";
export const FINALITY_CERTIFICATE_V2_FORMAT = "MT-FINALITY-CERTIFICATE-2";
export const MANIFEST_CHAIN_PROOF_FORMAT = "MT-MANIFEST-CHAIN-PROOF-1";
export const POP_DOMAIN = "MT-VALIDATOR-POP-1";
export const FINALITY_DOMAIN = "MT-FINALITY-V1";
export const TRANSITION_DOMAIN = "MT-VALIDATOR-SET-TRANSITION-1";
export const MANIFEST_CHAIN_BLOCK_DOMAIN = "MT-MANIFEST-CHAIN-BLOCK-1";
/** Motivo específico de autenticación de manifiesto (adjudicación §3.9). */
export const VALIDATOR_MANIFEST_HASH_MISMATCH = "VALIDATOR_MANIFEST_HASH_MISMATCH";
const HEX256_RE = /^[0-9a-f]{256}$/;
export function isHex256(v) {
    return typeof v === "string" && HEX256_RE.test(v);
}
function isObj(v) {
    return typeof v === "object" && v !== null && !Array.isArray(v);
}
function isSafeNonNegInt(v) {
    return typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
}
export const NETWORK_POLICIES = Object.freeze({
    testnet: Object.freeze({
        network_id: "testnet",
        chain_id: "million-tower-testnet-1",
        validator_count: 4,
        quorum: 3,
        cold_threshold: 2,
        cold_custodian_count: 3,
        max_simultaneous_replacements: 1,
    }),
    production: Object.freeze({
        network_id: "production",
        chain_id: "million-tower-1",
        validator_count: 7,
        quorum: 5,
        cold_threshold: 2,
        cold_custodian_count: 3,
        max_simultaneous_replacements: 2,
    }),
});
export function networkPolicy(networkId) {
    if (networkId === "testnet" || networkId === "production")
        return NETWORK_POLICIES[networkId];
    return undefined;
}
export function networkPolicyForChain(chainId) {
    if (chainId === NETWORK_POLICIES.testnet.chain_id)
        return NETWORK_POLICIES.testnet;
    if (chainId === NETWORK_POLICIES.production.chain_id)
        return NETWORK_POLICIES.production;
    return undefined;
}
export function buildFinalityPolicy(networkId) {
    const p = NETWORK_POLICIES[networkId];
    return {
        format: FINALITY_POLICY_FORMAT,
        chain_id: p.chain_id,
        network_id: networkId,
        validator_count: p.validator_count,
        quorum: p.quorum,
        signature_algorithm: "ML-DSA-87",
        finality_message_domain: FINALITY_DOMAIN,
        certificate_format: FINALITY_CERTIFICATE_V2_FORMAT,
    };
}
export function buildTransitionPolicy(networkId, coldAuthoritySeated) {
    const p = NETWORK_POLICIES[networkId];
    return {
        format: TRANSITION_POLICY_FORMAT,
        chain_id: p.chain_id,
        network_id: networkId,
        cold_signature_algorithm: "SLH-DSA-SHAKE-256s",
        cold_threshold: p.cold_threshold,
        cold_custodian_count: p.cold_custodian_count,
        cold_authority_seated: coldAuthoritySeated,
        max_simultaneous_replacements: p.max_simultaneous_replacements,
        requires_proof_of_possession: true,
        transition_message_domain: TRANSITION_DOMAIN,
    };
}
export function finalityPolicyHash(networkId) {
    return mtDual1024(canonicalBytes(buildFinalityPolicy(networkId)), FINALITY_POLICY_FORMAT);
}
export function transitionPolicyHash(networkId, coldAuthoritySeated) {
    return mtDual1024(canonicalBytes(buildTransitionPolicy(networkId, coldAuthoritySeated)), TRANSITION_POLICY_FORMAT);
}
/** Núcleo del manifiesto: el objeto SIN las pruebas de posesión. */
export function manifestCore(m) {
    return {
        format: m.format,
        schema_version: m.schema_version,
        chain_id: m.chain_id,
        network_id: m.network_id,
        epoch: m.epoch,
        effective_height: m.effective_height,
        prev_manifest_hash: m.prev_manifest_hash,
        finality_policy_hash: m.finality_policy_hash,
        transition_policy_hash: m.transition_policy_hash,
        validators: m.validators.map((v) => ({
            validator_id: v.validator_id,
            public_key: v.public_key,
            purpose: v.purpose,
        })),
    };
}
/** H(M) = MT-DUAL-1024(dominio ∥ JCS(núcleo)) — la identidad del manifiesto. */
export function canonicalManifestHash(m) {
    return mtDual1024(canonicalBytes(manifestCore(m)), MANIFEST_FORMAT);
}
/**
 * H(bootstrap) = MT-DUAL-1024(dominio ∥ JCS(bootstrap)) — el compromiso
 * del bootstrap ENTERO como objeto (remediación C-AUD-20, F-20-01).
 *
 * H(M0) compromete el manifiesto inicial, pero del bootstrap el
 * verificador solo contrastaba su `initial_manifest_hash` declarado:
 * el resto de su contenido —en particular `finality_activation_height`,
 * la altura que despacha qué versión de finalidad es exigible a cada
 * bloque— quedaba fuera de todo compromiso, y moverla con una
 * re-emisión coherente de la finalidad producía VALID declarando una
 * historia de versiones falsa. Este hash es el punto de ligadura: el
 * mismo patrón de dominio que H(M) y que los hashes de política (el
 * dominio es la cadena de formato del propio objeto). mt-verify lo
 * ancla como `bootstrap_hash` (ProofAnchors) y la publicación del
 * bootstrap (scripts/build-manifest-bootstrap.ts) lo acompaña desde
 * esta remediación.
 */
export function bootstrapHash(b) {
    return mtDual1024(canonicalBytes(b), BOOTSTRAP_FORMAT);
}
/** Mensaje exacto que firma cada clave nueva como prueba de posesión. */
export function popMessageBytes(args) {
    return canonicalBytes({
        domain: POP_DOMAIN,
        chain_id: args.chain_id,
        epoch: args.epoch,
        manifest_hash: args.manifest_hash,
        validator_id: args.validator_id,
        public_key: args.public_key,
    });
}
/**
 * Construye un manifiesto canónico: primero el núcleo y su huella, y
 * después la prueba de posesión de cada entrada firmando esa huella.
 * `popSigner` devuelve la firma base64 de cada validador sobre su
 * mensaje de posesión (custodia en la cadena; claves directas en las
 * baterías sintéticas).
 */
export function buildCanonicalManifest(args) {
    const policy = NETWORK_POLICIES[args.networkId];
    const base = {
        format: MANIFEST_FORMAT,
        schema_version: MANIFEST_SCHEMA_VERSION,
        chain_id: policy.chain_id,
        network_id: args.networkId,
        epoch: args.epoch,
        effective_height: args.effectiveHeight,
        prev_manifest_hash: args.prevManifestHash,
        finality_policy_hash: finalityPolicyHash(args.networkId),
        transition_policy_hash: transitionPolicyHash(args.networkId, args.coldAuthoritySeated),
        validators: args.entries.map((e) => ({
            validator_id: e.validator_id,
            public_key: e.public_key,
            purpose: "finality",
            proof_of_possession: "",
        })),
    };
    const hash = canonicalManifestHash(base);
    base.validators = base.validators.map((v) => ({
        ...v,
        proof_of_possession: args.popSigner(v.validator_id, popMessageBytes({
            chain_id: base.chain_id,
            epoch: base.epoch,
            manifest_hash: hash,
            validator_id: v.validator_id,
            public_key: v.public_key,
        })),
    }));
    return base;
}
/** Proyección operativa de un manifiesto canónico (la forma que consume
 *  verifyCertificate y el consenso): ids, claves y el quórum de la
 *  política de red autenticada — nunca un quórum declarado. */
export function operationalManifest(m) {
    const policy = NETWORK_POLICIES[m.network_id];
    return {
        format: MANIFEST_FORMAT,
        chain_id: m.chain_id,
        quorum: policy.quorum,
        validators: m.validators.map((v) => ({ validator_id: v.validator_id, public_key: v.public_key })),
    };
}
export function buildBootstrap(args) {
    const policy = NETWORK_POLICIES[args.networkId];
    return {
        format: BOOTSTRAP_FORMAT,
        chain_id: policy.chain_id,
        network_id: args.networkId,
        genesis_hash: args.genesisHash,
        bootstrap_epoch: args.bootstrapEpoch,
        bootstrap_height: args.bootstrapHeight,
        initial_manifest_hash: args.initialManifestHash,
        finality_policy_hash: finalityPolicyHash(args.networkId),
        transition_policy_hash: transitionPolicyHash(args.networkId, args.coldAuthority !== null),
        cold_authority: args.coldAuthority,
        finality_activation_height: args.finalityActivationHeight,
    };
}
/** El tuplo vinculante único que firman ambas autorizaciones. */
export function transitionTuple(t) {
    return {
        domain: TRANSITION_DOMAIN,
        chain_id: t.chain_id,
        old_epoch: t.old_epoch,
        new_epoch: t.new_epoch,
        old_manifest_hash: t.old_manifest_hash,
        new_manifest_hash: t.new_manifest_hash,
        transition_height: t.transition_height,
        effective_height: t.effective_height,
        transition_policy_hash: t.transition_policy_hash,
        nonce: t.nonce,
    };
}
export function transitionTupleBytes(t) {
    return canonicalBytes(transitionTuple(t));
}
/** Huella del objeto de transición completo (lo que compromete su bloque). */
export function setTransitionHash(t) {
    return mtDual1024(canonicalBytes(t), TRANSITION_DOMAIN);
}
/** Supervivientes entre dos manifiestos: ids presentes en ambos con la
 *  MISMA clave. Todo lo demás es sustitución (retiro, alta o rotación). */
export function survivorIds(oldM, newM) {
    const newById = new Map(newM.validators.map((v) => [v.validator_id, v.public_key]));
    const oldById = new Map(oldM.validators.map((v) => [v.validator_id, v.public_key]));
    const survivors = [];
    const retired = [];
    for (const v of oldM.validators) {
        if (newById.get(v.validator_id) === v.public_key)
            survivors.push(v.validator_id);
        else
            retired.push(v.validator_id);
    }
    const added = [];
    for (const v of newM.validators) {
        if (oldById.get(v.validator_id) !== v.public_key)
            added.push(v.validator_id);
    }
    const sort = (a) => [...a].sort();
    return { survivors: sort(survivors), retired: sort(retired), added: sort(added) };
}
/**
 * Construye una transición E-19 completa: deriva retirados/añadidos de
 * los dos manifiestos, forma el tuplo y recoge las dos autorizaciones
 * sobre ÉL (supervivientes con su clave ML-DSA-87; custodios fríos con
 * sus claves SLH-DSA independientes).
 */
export function buildSetTransition(args) {
    const { retired, added } = survivorIds(args.oldManifest, args.newManifest);
    const t = {
        format: TRANSITION_FORMAT,
        schema_version: MANIFEST_SCHEMA_VERSION,
        chain_id: args.oldManifest.chain_id,
        network_id: args.oldManifest.network_id,
        old_epoch: args.oldManifest.epoch,
        new_epoch: args.newManifest.epoch,
        old_manifest_hash: canonicalManifestHash(args.oldManifest),
        new_manifest_hash: canonicalManifestHash(args.newManifest),
        transition_height: args.transitionHeight,
        effective_height: args.transitionHeight + 1,
        transition_policy_hash: args.oldManifest.transition_policy_hash,
        nonce: args.nonce,
        retired_validator_ids: retired,
        added_validator_ids: added,
        survivor_signatures: [],
        cold_signatures: [],
    };
    const bytes = transitionTupleBytes(t);
    const survivors = survivorIds(args.oldManifest, args.newManifest).survivors;
    const signers = [...(args.signerIds ?? survivors)].sort();
    t.survivor_signatures = signers.map((id) => ({
        validator_id: id,
        signature: args.survivorSigner(id, bytes),
    }));
    return t;
}
/** Añade las firmas frías a una transición ya construida (custodios dados). */
export function withColdSignatures(t, coldSigner, custodianIds) {
    const bytes = transitionTupleBytes(t);
    return {
        ...t,
        cold_signatures: [...custodianIds].sort().map((id) => ({
            custodian_id: id,
            signature: coldSigner(id, bytes),
        })),
    };
}
/** Mensaje firmado de finalidad v2: dominio MT-FINALITY-V1 con cadena,
 *  época, altura (= sequence), vista (0: este consenso no tiene cambio
 *  de vista) y la huella del manifiesto vigente. */
export function finalityMessageV2Bytes(args) {
    const t = args.transition;
    return canonicalBytes({
        domain: FINALITY_DOMAIN,
        chain_id: t.chain_id,
        kind: t.kind,
        sequence: t.sequence,
        prev_state: t.prev_state,
        transition_hash: t.transition_hash,
        epoch: args.epoch,
        view: 0,
        manifest_hash: args.manifest_hash,
    });
}
export function buildFinalityCertificateV2(args) {
    const manifest_hash = canonicalManifestHash(args.manifest);
    const bytes = finalityMessageV2Bytes({
        transition: args.transition,
        epoch: args.manifest.epoch,
        manifest_hash,
    });
    const ids = [...(args.signerIds ?? args.manifest.validators.map((v) => v.validator_id))].sort();
    return {
        format: FINALITY_CERTIFICATE_V2_FORMAT,
        transition: { ...args.transition },
        epoch: args.manifest.epoch,
        manifest_hash,
        votes: ids.map((id) => ({ validator_id: id, signature: args.signer(id, bytes) })),
    };
}
/**
 * Verificación de un certificado v2 contra el manifiesto vigente
 * (lado productor; mt-verify reimplementa el mismo juicio).
 * Reglas: esquema cerrado en certificado, descriptor y votos; votos en
 * orden estrictamente ascendente por validator_id (presentación
 * canónica); epoch y manifest_hash del certificado IGUALES a los del
 * manifiesto vigente; firmantes distintos del manifiesto; firmas sobre
 * el mensaje MT-FINALITY-V1; quórum de la política de red.
 */
export function verifyFinalityCertificateV2(manifest, cert) {
    const errors = [];
    if (!isObj(cert))
        return { valid: false, distinct_signers: 0, errors: ["El certificado no es un objeto"] };
    const extraCert = firstUnknownField(cert, FINALITY_CERTIFICATE_V2_FIELDS);
    if (extraCert !== null)
        errors.push(schemaFieldNotAllowedMessage("el certificado de finalidad v2", extraCert));
    if (cert.format !== FINALITY_CERTIFICATE_V2_FORMAT) {
        errors.push(`El certificado no es un ${FINALITY_CERTIFICATE_V2_FORMAT} (format=${JSON.stringify(cert.format)})`);
    }
    const extraTrans = firstUnknownField(cert?.transition, TRANSITION_DESCRIPTOR_FIELDS);
    if (extraTrans !== null)
        errors.push(schemaFieldNotAllowedMessage("el descriptor de transición del certificado v2", extraTrans));
    if (Array.isArray(cert?.votes)) {
        for (const vote of cert.votes) {
            const extraVote = firstUnknownField(vote, VOTE_FIELDS);
            if (extraVote !== null)
                errors.push(schemaFieldNotAllowedMessage("un voto del certificado v2", extraVote));
        }
    }
    if (errors.length > 0)
        return { valid: false, distinct_signers: 0, errors };
    const policy = NETWORK_POLICIES[manifest.network_id];
    const expectedHash = canonicalManifestHash(manifest);
    if (cert.epoch !== manifest.epoch) {
        errors.push(`El certificado declara epoch=${cert.epoch} y el manifiesto vigente es la época ${manifest.epoch}`);
    }
    if (cert.manifest_hash !== expectedHash) {
        errors.push(`${VALIDATOR_MANIFEST_HASH_MISMATCH}: el certificado declara manifest_hash=${cert.manifest_hash} y el manifiesto vigente hashea ${expectedHash}`);
    }
    if (cert.transition.chain_id !== manifest.chain_id) {
        errors.push(`El certificado es de otra cadena (${cert.transition.chain_id} != ${manifest.chain_id})`);
    }
    const ids = cert.votes.map((v) => v.validator_id);
    for (let i = 1; i < ids.length; i++) {
        if (ids[i - 1] >= ids[i]) {
            errors.push("Los votos no están en orden estrictamente ascendente por validator_id (presentación canónica)");
            break;
        }
    }
    const byId = new Map(manifest.validators.map((v) => [v.validator_id, v.public_key]));
    const distinct = new Set();
    let bytes;
    try {
        bytes = finalityMessageV2Bytes({ transition: cert.transition, epoch: cert.epoch, manifest_hash: cert.manifest_hash });
    }
    catch {
        errors.push("El certificado no se puede canonicalizar para recomputar su mensaje firmado");
    }
    if (bytes) {
        for (const vote of cert.votes) {
            const key = byId.get(vote.validator_id);
            if (!key) {
                errors.push(`Voto de un validador fuera del manifiesto vigente: ${vote.validator_id}`);
                continue;
            }
            if (!verifyMlDsa87(key, bytes, Buffer.from(vote.signature, "base64"))) {
                errors.push(`Firma inválida de ${vote.validator_id} sobre el mensaje MT-FINALITY-V1`);
                continue;
            }
            distinct.add(vote.validator_id);
        }
    }
    if (distinct.size < policy.quorum) {
        errors.push(`Quórum no alcanzado: ${distinct.size}/${policy.quorum} firmantes distintos`);
    }
    return { valid: errors.length === 0, distinct_signers: distinct.size, errors };
}
/** ¿Tiene este objeto la forma de un certificado v2? (despacho por formato) */
export function isFinalityCertificateV2(cert) {
    return isObj(cert) && cert.format === FINALITY_CERTIFICATE_V2_FORMAT;
}
/**
 * Colector de finalidad v2 (MOTOR 2 — emisión del productor): recoge el
 * certificado MT-FINALITY-CERTIFICATE-2 de una transición firmando el
 * mensaje MT-FINALITY-V1 a través de la custodia duradera del conjunto
 * (ValidatorSet.signLedgerBound: compromiso con fsync antes de firmar,
 * firma persistida antes de entregarse — la misma ley de hierro que el
 * colector v1). Es el espejo v2 de validators.collectCertificate.
 *
 * Como el colector v1 (FinalityCollector), este colector EMPAREJA cada
 * firma con el mensaje de su versión antes de ensamblar: la custodia
 * liga por (kind, sequence, transition_hash) y su devolución
 * idempotente no re-verifica (fijado por A7-IMP-03), así que si la
 * transición ya se finalizó en v1, signLedgerBound devuelve las firmas
 * v1 — y aquí se rechazan con CONSENSUS_INVALID_SIGNATURE, el mismo
 * código y la misma capa (el colector) que el juicio v1. Una
 * transición se finaliza en UNA sola versión; qué versión toca lo
 * decide la activación versionada de la cadena, no el llamante.
 */
export function collectCertificateV2(set, d, manifest, signerIds) {
    const cert = buildFinalityCertificateV2({
        transition: d,
        manifest,
        signer: (id, message) => set.signLedgerBound(id, d, message).signature,
        signerIds,
    });
    const bytes = finalityMessageV2Bytes({
        transition: d,
        epoch: manifest.epoch,
        manifest_hash: canonicalManifestHash(manifest),
    });
    const byId = new Map(manifest.validators.map((v) => [v.validator_id, v.public_key]));
    for (const vote of cert.votes) {
        const publicKey = byId.get(vote.validator_id);
        if (!publicKey || !verifyMlDsa87(publicKey, bytes, Buffer.from(vote.signature, "base64"))) {
            throw new ConsensusError("CONSENSUS_INVALID_SIGNATURE", `${vote.validator_id} devolvió una firma que no verifica sobre el mensaje MT-FINALITY-V1 de ${d.kind}#${d.sequence}: la transición ya estaba finalizada en otra versión (v1) o la firma no corresponde a este descriptor`);
        }
    }
    return cert;
}
/**
 * Sección para una cadena con UN solo manifiesto (sin transiciones en
 * su historia): la construye quien tiene la custodia del conjunto
 * (firmas de posesión reales). La autoridad fría de la testnet es null:
 * nunca sentó custodios. La activación de finalidad v2 queda en la
 * primera altura que la cadena aún no ha producido (activationHeight).
 */
export function buildSingleManifestSection(args) {
    const m0 = buildCanonicalManifest({
        networkId: args.networkId,
        epoch: 0,
        effectiveHeight: 0,
        prevManifestHash: null,
        coldAuthoritySeated: false,
        entries: args.entries,
        popSigner: args.popSigner,
    });
    const bootstrap = buildBootstrap({
        networkId: args.networkId,
        genesisHash: args.genesisHash,
        bootstrapEpoch: 0,
        bootstrapHeight: 0,
        initialManifestHash: canonicalManifestHash(m0),
        coldAuthority: null,
        finalityActivationHeight: args.activationHeight,
    });
    return { bootstrap, manifests: [m0], transitions: [] };
}
/** Sección de la testnet desde la custodia de un ValidatorSet. */
export function buildTestnetSectionFromSet(set, genesisHash, activationHeight) {
    return buildSingleManifestSection({
        networkId: "testnet",
        genesisHash,
        activationHeight,
        entries: set.manifest.validators.map((v) => ({ validator_id: v.validator_id, public_key: v.public_key })),
        popSigner: (id, msg) => set.signAdmissionProof(id, msg),
    });
}
function strictlyAscending(ids) {
    for (let i = 1; i < ids.length; i++)
        if (ids[i - 1] >= ids[i])
            return false;
    return true;
}
/**
 * Juicio completo sobre una sección de cadena de manifiestos:
 * esquema cerrado y forma de bootstrap, manifiestos y transiciones;
 * políticas contra la raíz; encadenamiento sin huecos; pruebas de
 * posesión; autorización de cada transición (quórum de supervivientes
 * del conjunto saliente, autoridad fría 2-de-3 sobre el MISMO tuplo,
 * tope de sustituciones simultáneas, anti-replay por nonce y tuplo).
 * NO contrasta anclas del llamante (eso es de mt-verify con sus anclas)
 * ni juzga bloques: es la mitad «cadena» del juicio.
 */
export function validateManifestChain(sectionInput, opts) {
    const errors = [];
    const fail = (msg) => {
        errors.push(msg);
    };
    const empty = {
        errors,
        manifestHashes: [],
        manifestAtHeight: () => undefined,
    };
    if (!isObj(sectionInput)) {
        fail("La sección de cadena de manifiestos no es un objeto");
        return empty;
    }
    const section = sectionInput;
    const secExtra = firstUnknownField(section, MANIFEST_CHAIN_SECTION_FIELDS);
    if (secExtra !== null)
        fail(schemaFieldNotAllowedMessage("la sección de cadena de manifiestos", secExtra));
    const bootstrap = section.bootstrap;
    if (!isObj(bootstrap)) {
        fail("La sección no trae el objeto bootstrap MT-VALIDATOR-MANIFEST-BOOTSTRAP-1");
        return empty;
    }
    const bExtra = firstUnknownField(bootstrap, MANIFEST_BOOTSTRAP_FIELDS);
    if (bExtra !== null)
        fail(schemaFieldNotAllowedMessage("el bootstrap de manifiestos", bExtra));
    if (bootstrap.format !== BOOTSTRAP_FORMAT) {
        fail(`El bootstrap no es un ${BOOTSTRAP_FORMAT} (format=${JSON.stringify(bootstrap.format)})`);
    }
    const policy = networkPolicy(bootstrap.network_id);
    if (!policy) {
        fail(`El bootstrap declara una red desconocida: ${JSON.stringify(bootstrap.network_id)}`);
        return { ...empty, errors };
    }
    if (bootstrap.chain_id !== opts.chainId || bootstrap.chain_id !== policy.chain_id) {
        fail(`El bootstrap es de otra cadena (${JSON.stringify(bootstrap.chain_id)} != ${opts.chainId})`);
    }
    if (!isHex256(bootstrap.genesis_hash))
        fail("El bootstrap no trae un genesis_hash MT-DUAL-1024");
    else if (opts.genesisHash !== undefined && bootstrap.genesis_hash !== opts.genesisHash) {
        fail("El genesis_hash del bootstrap no coincide con el génesis del paquete");
    }
    if (!isSafeNonNegInt(bootstrap.bootstrap_epoch))
        fail("bootstrap_epoch malformado");
    if (!isSafeNonNegInt(bootstrap.bootstrap_height))
        fail("bootstrap_height malformado");
    if (!isSafeNonNegInt(bootstrap.finality_activation_height))
        fail("finality_activation_height malformado");
    if (!isHex256(bootstrap.initial_manifest_hash))
        fail("El bootstrap no trae un initial_manifest_hash MT-DUAL-1024");
    const coldSeated = bootstrap.cold_authority !== null && bootstrap.cold_authority !== undefined;
    if (bootstrap.finality_policy_hash !== finalityPolicyHash(policy.network_id)) {
        fail("La finality_policy_hash del bootstrap no coincide con la política de finalidad autenticada de la red");
    }
    if (bootstrap.transition_policy_hash !== transitionPolicyHash(policy.network_id, coldSeated)) {
        fail("La transition_policy_hash del bootstrap no coincide con la política de transición autenticada de la red");
    }
    let cold;
    if (coldSeated) {
        const ca = bootstrap.cold_authority;
        const caExtra = firstUnknownField(ca, COLD_AUTHORITY_FIELDS);
        if (caExtra !== null)
            fail(schemaFieldNotAllowedMessage("la autoridad fría del bootstrap", caExtra));
        if (ca.threshold !== policy.cold_threshold) {
            fail(`El umbral de la autoridad fría debe ser ${policy.cold_threshold} (política autenticada); declara ${JSON.stringify(ca.threshold)}`);
        }
        if (!Array.isArray(ca.custodians) || ca.custodians.length !== policy.cold_custodian_count) {
            fail(`La autoridad fría debe tener ${policy.cold_custodian_count} custodios; declara ${Array.isArray(ca.custodians) ? ca.custodians.length : "ninguno"}`);
        }
        else {
            const cids = new Set();
            const ckeys = new Set();
            ca.custodians.forEach((c, i) => {
                if (!isObj(c)) {
                    fail(`El custodio frío ${i} no es un objeto`);
                    return;
                }
                const cExtra = firstUnknownField(c, COLD_CUSTODIAN_FIELDS);
                if (cExtra !== null)
                    fail(schemaFieldNotAllowedMessage(`el custodio frío ${i}`, cExtra));
                if (typeof c.custodian_id !== "string" || c.custodian_id.length === 0)
                    fail(`El custodio frío ${i} no declara custodian_id`);
                else if (cids.has(c.custodian_id))
                    fail(`custodian_id duplicado en la autoridad fría: ${c.custodian_id}`);
                else
                    cids.add(c.custodian_id);
                if (typeof c.public_key !== "string" || c.public_key.length === 0)
                    fail(`El custodio frío ${i} no declara clave pública`);
                else if (!isSlhDsaShake256sPublicKey(c.public_key))
                    fail(`La clave del custodio frío ${i} no es una clave pública SLH-DSA-SHAKE-256s canónica`);
                else if (ckeys.has(c.public_key))
                    fail("Dos custodios fríos comparten la misma clave pública");
                else
                    ckeys.add(c.public_key);
            });
            cold = ca;
        }
    }
    const manifests = section.manifests;
    if (!Array.isArray(manifests) || manifests.length === 0) {
        fail("La sección no trae manifiestos");
        return { ...empty, errors };
    }
    const transitions = Array.isArray(section.transitions) ? section.transitions : [];
    if (!Array.isArray(section.transitions))
        fail("La sección no trae la lista de transiciones");
    if (transitions.length !== manifests.length - 1) {
        fail(`La cadena trae ${manifests.length} manifiestos y ${transitions.length} transiciones (debe haber exactamente una transición por sucesor)`);
    }
    const hashes = [];
    manifests.forEach((m, i) => {
        if (!isObj(m)) {
            fail(`El manifiesto ${i} no es un objeto`);
            hashes.push("");
            return;
        }
        const mExtra = firstUnknownField(m, CANONICAL_MANIFEST_FIELDS);
        if (mExtra !== null)
            fail(schemaFieldNotAllowedMessage(`el manifiesto canónico ${i}`, mExtra));
        if (m.format !== MANIFEST_FORMAT || m.schema_version !== MANIFEST_SCHEMA_VERSION) {
            fail(`El manifiesto ${i} no es un ${MANIFEST_FORMAT} schema_version "1"`);
        }
        if (m.chain_id !== opts.chainId || m.network_id !== policy.network_id) {
            fail(`El manifiesto ${i} no es de esta cadena/red`);
        }
        if (m.epoch !== bootstrap.bootstrap_epoch + i) {
            fail(`El manifiesto ${i} declara epoch=${m.epoch}; la cadena exige épocas consecutivas desde ${bootstrap.bootstrap_epoch} (saltos de época no admitidos)`);
        }
        if (!isSafeNonNegInt(m.effective_height))
            fail(`El manifiesto ${i} no trae una effective_height válida`);
        else if (i === 0 && m.effective_height !== bootstrap.bootstrap_height) {
            fail(`El manifiesto inicial tiene effective_height=${m.effective_height} y el bootstrap declara el corte en ${bootstrap.bootstrap_height}`);
        }
        else if (i > 0 && isSafeNonNegInt(manifests[i - 1]?.effective_height) && m.effective_height <= manifests[i - 1].effective_height) {
            fail(`El manifiesto ${i} no entra en vigor tras el anterior (effective_height no estrictamente creciente)`);
        }
        if (i === 0) {
            if (m.epoch === 0 && m.prev_manifest_hash !== null) {
                fail("El manifiesto de la época 0 debe declarar prev_manifest_hash null");
            }
            else if (m.epoch > 0 && !isHex256(m.prev_manifest_hash)) {
                fail("El manifiesto inicial con corte debe declarar la huella (no verificable aquí) de su predecesor");
            }
        }
        else if (m.prev_manifest_hash !== hashes[i - 1]) {
            fail(`${VALIDATOR_MANIFEST_HASH_MISMATCH}: el manifiesto ${i} declara prev_manifest_hash distinto de la huella del manifiesto ${i - 1}`);
        }
        if (m.finality_policy_hash !== bootstrap.finality_policy_hash) {
            fail(`El manifiesto ${i} declara una finality_policy_hash distinta de la anclada en la raíz (política de finalidad cambiada desde el manifiesto)`);
        }
        if (m.transition_policy_hash !== bootstrap.transition_policy_hash) {
            fail(`El manifiesto ${i} declara una transition_policy_hash distinta de la anclada en la raíz`);
        }
        if (!Array.isArray(m.validators) || m.validators.length !== policy.validator_count) {
            fail(`El manifiesto ${i} debe tener ${policy.validator_count} validadores (política autenticada); trae ${Array.isArray(m.validators) ? m.validators.length : "ninguno"}`);
            hashes.push("");
            return;
        }
        const ids = new Set();
        const keys = new Set();
        m.validators.forEach((v, j) => {
            if (!isObj(v)) {
                fail(`La entrada ${j} del manifiesto ${i} no es un objeto`);
                return;
            }
            const vExtra = firstUnknownField(v, CANONICAL_MANIFEST_ENTRY_FIELDS);
            if (vExtra !== null)
                fail(schemaFieldNotAllowedMessage(`la entrada ${j} del manifiesto ${i}`, vExtra));
            if (typeof v.validator_id !== "string" || v.validator_id.length === 0)
                fail(`La entrada ${j} del manifiesto ${i} no declara validator_id`);
            else if (ids.has(v.validator_id))
                fail(`validator_id duplicado en el manifiesto ${i}: ${v.validator_id}`);
            else
                ids.add(v.validator_id);
            if (typeof v.public_key !== "string" || v.public_key.length === 0)
                fail(`La entrada ${j} del manifiesto ${i} no declara clave pública`);
            else if (!isMlDsa87PublicKey(v.public_key))
                fail(`La clave de la entrada ${j} del manifiesto ${i} no es una clave pública ML-DSA-87 canónica`);
            else if (keys.has(v.public_key))
                fail(`La misma clave pública sirve a dos validadores en el manifiesto ${i}`);
            else
                keys.add(v.public_key);
            if (v.purpose !== "finality")
                fail(`La entrada ${j} del manifiesto ${i} declara un propósito no autorizado: ${JSON.stringify(v.purpose)}`);
        });
        let hash = "";
        try {
            hash = canonicalManifestHash(m);
        }
        catch {
            fail(`El manifiesto ${i} no se puede canonicalizar para recomputar su huella`);
        }
        hashes.push(hash);
        // Pruebas de posesión: cada clave firma H(M) en su mensaje MT-VALIDATOR-POP-1.
        if (hash) {
            for (const v of m.validators) {
                if (!isObj(v) || typeof v.public_key !== "string" || typeof v.proof_of_possession !== "string") {
                    fail(`La entrada de ${JSON.stringify(v?.validator_id)} del manifiesto ${i} no trae prueba de posesión`);
                    continue;
                }
                const msg = popMessageBytes({
                    chain_id: m.chain_id,
                    epoch: m.epoch,
                    manifest_hash: hash,
                    validator_id: v.validator_id,
                    public_key: v.public_key,
                });
                if (!verifyMlDsa87(v.public_key, msg, Buffer.from(v.proof_of_possession, "base64"))) {
                    fail(`Prueba de posesión inválida o ausente de ${v.validator_id} en el manifiesto ${i}`);
                }
            }
        }
    });
    if (hashes[0] && isHex256(bootstrap.initial_manifest_hash) && hashes[0] !== bootstrap.initial_manifest_hash) {
        fail(`${VALIDATOR_MANIFEST_HASH_MISMATCH}: la huella del manifiesto inicial presentado (${hashes[0]}) no coincide con la comprometida en el bootstrap (${bootstrap.initial_manifest_hash})`);
    }
    const seenNonces = new Set();
    const seenTuples = new Set();
    transitions.forEach((t, i) => {
        const from = manifests[i];
        const to = manifests[i + 1];
        if (!isObj(t) || !isObj(from) || !isObj(to)) {
            fail(`La transición ${i} o sus manifiestos no son objetos`);
            return;
        }
        const tExtra = firstUnknownField(t, SET_TRANSITION_FIELDS);
        if (tExtra !== null)
            fail(schemaFieldNotAllowedMessage(`la transición ${i}`, tExtra));
        if (t.format !== TRANSITION_FORMAT || t.schema_version !== MANIFEST_SCHEMA_VERSION) {
            fail(`La transición ${i} no es un ${TRANSITION_FORMAT} schema_version "1"`);
        }
        if (t.chain_id !== opts.chainId || t.network_id !== policy.network_id) {
            fail(`La transición ${i} no es de esta cadena/red`);
        }
        if (t.old_epoch !== from.epoch || t.new_epoch !== to.epoch || t.new_epoch !== t.old_epoch + 1) {
            fail(`La transición ${i} no enlaza épocas consecutivas (${t.old_epoch} → ${t.new_epoch} frente a ${from.epoch} → ${to.epoch})`);
        }
        if (t.old_manifest_hash !== hashes[i]) {
            fail(`${VALIDATOR_MANIFEST_HASH_MISMATCH}: la transición ${i} no coincide con el manifiesto anterior (old_manifest_hash distinto de su huella)`);
        }
        if (t.new_manifest_hash !== hashes[i + 1]) {
            fail(`${VALIDATOR_MANIFEST_HASH_MISMATCH}: la transición ${i} no coincide con el manifiesto sucesor (new_manifest_hash distinto de su huella)`);
        }
        if (t.effective_height !== to.effective_height || t.transition_height !== t.effective_height - 1) {
            fail(`La transición ${i} declara alturas incoherentes (transition_height=${t.transition_height}, effective_height=${t.effective_height}, en vigor del sucesor=${to.effective_height})`);
        }
        if (isSafeNonNegInt(from.effective_height) && t.transition_height < from.effective_height) {
            fail(`La transición ${i} se produce antes de que el conjunto saliente entrara en vigor (activación retroactiva)`);
        }
        if (t.transition_policy_hash !== bootstrap.transition_policy_hash) {
            fail(`La transición ${i} declara una transition_policy_hash distinta de la anclada en la raíz`);
        }
        if (typeof t.nonce !== "string" || t.nonce.length === 0)
            fail(`La transición ${i} no trae nonce`);
        else if (seenNonces.has(t.nonce))
            fail(`La transición ${i} reutiliza el nonce ${JSON.stringify(t.nonce)} (replay de transición)`);
        else
            seenNonces.add(t.nonce);
        let tupleKey = "";
        try {
            tupleKey = JSON.stringify(transitionTuple(t));
        }
        catch {
            fail(`La transición ${i} no se puede canonicalizar`);
        }
        if (tupleKey) {
            if (seenTuples.has(tupleKey))
                fail(`La transición ${i} repite el tuplo de otra transición (replay)`);
            else
                seenTuples.add(tupleKey);
        }
        // Retirados/añadidos derivados — la declaración debe coincidir EXACTO.
        const { survivors, retired, added } = survivorIds(from, to);
        const eqArr = (a, b) => Array.isArray(a) && a.length === b.length && a.every((x, j) => x === b[j]);
        if (!eqArr(t.retired_validator_ids, retired)) {
            fail(`La transición ${i} no declara los retirados derivados de los manifiestos (${JSON.stringify(t.retired_validator_ids)} != ${JSON.stringify(retired)})`);
        }
        if (!eqArr(t.added_validator_ids, added)) {
            fail(`La transición ${i} no declara los añadidos derivados de los manifiestos (${JSON.stringify(t.added_validator_ids)} != ${JSON.stringify(added)})`);
        }
        if (retired.length === 0) {
            fail(`La transición ${i} no sustituye a nadie: una transición sin cambios no es una ceremonia E-19 válida`);
        }
        if (retired.length > policy.max_simultaneous_replacements) {
            fail(`La transición ${i} sustituye ${retired.length} validadores a la vez; el tope autenticado es ${policy.max_simultaneous_replacements} (deben quedar al menos ${policy.quorum} supervivientes que firmen): detención, no transición`);
        }
        // Autorización 1: quórum de SUPERVIVIENTES del conjunto saliente.
        let tupleBytes;
        try {
            tupleBytes = transitionTupleBytes(t);
        }
        catch {
            fail(`La transición ${i} no se puede canonicalizar para verificar sus firmas`);
        }
        const fromKeys = new Map(from.validators.map((v) => [v.validator_id, v.public_key]));
        const sigs = Array.isArray(t.survivor_signatures) ? t.survivor_signatures : [];
        if (!Array.isArray(t.survivor_signatures))
            fail(`La transición ${i} no trae survivor_signatures`);
        if (!strictlyAscending(sigs.map((s) => (isObj(s) ? String(s.validator_id) : "")))) {
            fail(`Las firmas de supervivientes de la transición ${i} no están en orden estrictamente ascendente por validator_id (presentación canónica)`);
        }
        const survivorSigners = new Set();
        for (const s of sigs) {
            if (!isObj(s)) {
                fail(`Una firma de superviviente de la transición ${i} no es un objeto`);
                continue;
            }
            const sExtra = firstUnknownField(s, SURVIVOR_SIGNATURE_FIELDS);
            if (sExtra !== null)
                fail(schemaFieldNotAllowedMessage(`una firma de superviviente de la transición ${i}`, sExtra));
            if (typeof s.validator_id !== "string" || typeof s.signature !== "string") {
                fail(`Una firma de superviviente de la transición ${i} está malformada`);
                continue;
            }
            if (!survivors.includes(s.validator_id)) {
                fail(`La transición ${i} cuenta como superviviente a ${s.validator_id}, que no lo es (retirado, rotado o ajeno al conjunto saliente)`);
                continue;
            }
            if (tupleBytes && !verifyMlDsa87(fromKeys.get(s.validator_id), tupleBytes, Buffer.from(s.signature, "base64"))) {
                fail(`Firma de superviviente inválida de ${s.validator_id} en la transición ${i} (no firma este tuplo)`);
                continue;
            }
            survivorSigners.add(s.validator_id);
        }
        if (survivorSigners.size < policy.quorum) {
            fail(`La transición ${i} no alcanza el quórum de supervivientes: ${survivorSigners.size}/${policy.quorum} firmantes distintos del conjunto saliente`);
        }
        // Autorización 2: autoridad fría 2-de-3 sobre el MISMO tuplo (E-19).
        if (!cold) {
            fail(`La transición ${i} es una ceremonia E-19 pero la red no tiene autoridad fría asentada en la raíz: ninguna transición es autorizable`);
        }
        else {
            const csigs = Array.isArray(t.cold_signatures) ? t.cold_signatures : [];
            if (!Array.isArray(t.cold_signatures))
                fail(`La transición ${i} no trae cold_signatures`);
            if (!strictlyAscending(csigs.map((s) => (isObj(s) ? String(s.custodian_id) : "")))) {
                fail(`Las firmas frías de la transición ${i} no están en orden estrictamente ascendente por custodian_id (presentación canónica)`);
            }
            const coldKeys = new Map(cold.custodians.map((c) => [c.custodian_id, c.public_key]));
            const coldSigners = new Set();
            for (const s of csigs) {
                if (!isObj(s)) {
                    fail(`Una firma fría de la transición ${i} no es un objeto`);
                    continue;
                }
                const sExtra = firstUnknownField(s, COLD_SIGNATURE_FIELDS);
                if (sExtra !== null)
                    fail(schemaFieldNotAllowedMessage(`una firma fría de la transición ${i}`, sExtra));
                if (typeof s.custodian_id !== "string" || typeof s.signature !== "string") {
                    fail(`Una firma fría de la transición ${i} está malformada`);
                    continue;
                }
                const key = coldKeys.get(s.custodian_id);
                if (!key) {
                    fail(`La transición ${i} trae una firma fría de ${s.custodian_id}, que no es custodio de la autoridad fría anclada en la raíz`);
                    continue;
                }
                if (tupleBytes && !verifySlhDsaShake256s(key, tupleBytes, Buffer.from(s.signature, "base64"))) {
                    fail(`Firma fría inválida de ${s.custodian_id} en la transición ${i} (no firma este tuplo)`);
                    continue;
                }
                coldSigners.add(s.custodian_id);
            }
            if (coldSigners.size < policy.cold_threshold) {
                fail(`La transición ${i} no alcanza la autoridad fría ${policy.cold_threshold}-de-${policy.cold_custodian_count}: ${coldSigners.size} firmas frías independientes`);
            }
        }
    });
    const current = errors.length === 0 ? manifests[manifests.length - 1] : undefined;
    return {
        errors,
        manifestHashes: hashes,
        ...(current ? { current } : {}),
        manifestAtHeight: (h) => {
            let found;
            for (const m of manifests) {
                if (isObj(m) && isSafeNonNegInt(m.effective_height) && m.effective_height <= h) {
                    found = m;
                }
            }
            return found;
        },
    };
}
/** Huella de un bloque de la evidencia: compromete altura, tipo,
 *  encadenamiento y —en su caso— la transición completa que introduce. */
export function manifestChainBlockHash(core) {
    return mtDual1024(canonicalBytes(core), MANIFEST_CHAIN_BLOCK_DOMAIN);
}
/** Descriptor de finalidad de un bloque de la evidencia. */
export function manifestChainBlockDescriptor(block, chainId) {
    return {
        chain_id: chainId,
        kind: block.kind === "GENESIS" ? "GENESIS" : block.kind === "VALIDATOR_SET_TRANSITION" ? "VALIDATOR_SET_TRANSITION" : "MINT_BRICK",
        sequence: block.height,
        prev_state: block.prev_hash,
        transition_hash: block.block_hash,
    };
}
export { ZERO_HASH_1024 };
