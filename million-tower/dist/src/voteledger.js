/**
 * MT-VOTELEDGER-2 · Registro duradero de votos con custodia previa a la firma.
 *
 * Cierre del bloqueante de reinicio (artefacto 13 en la numeración de
 * DeepSeek; «12» en la numeración original de la casa): hasta R5 el
 * VoteLedger era volátil — tras un reinicio la custodia «olvidaba» qué había
 * votado y podía firmar una transición conflictiva para la misma secuencia
 * (hueco documentado en EVIDENCIA-PQ-consenso-formal.md §4, probado en
 * battery13 CON-05). Este módulo es la frontera de custodia que lo cierra:
 *
 * PIPELINE OBLIGATORIO (orden exacto, sin atajos):
 *   (i)   petición de voto (cadena, época del conjunto, validador, tipo,
 *         secuencia, estado previo, huella de la transición);
 *   (ii)  validación anti-equivocación contra el estado duradero restaurado;
 *   (iii) escritura APPEND-ONLY encadenada por hash, con checksum por
 *         entrada y FSYNC completado del compromiso de voto;
 *   (iv)  SOLO ENTONCES el llamante puede emitir la firma ML-DSA-87, y la
 *         firma producida se persiste (otra entrada + fsync) ANTES de ser
 *         entregada al solicitante;
 *   (v)   publicación del voto/certificado: responsabilidad del llamante,
 *         aguas abajo de esta custodia.
 *
 * Una firma NUNCA se emite antes de persistir su compromiso. Un fsync
 * fallido BLOQUEA la firma: la instancia queda detenida (fail-closed) y el
 * llamante debe descartar cualquier firma producida en esa operación.
 * Re-votar la transición IDÉNTICA es idempotente: se devuelve la firma
 * original registrada, jamás una segunda firma distinta.
 *
 * INTEGRIDAD: cada entrada enlaza el checksum (MT-DUAL-1024) de la anterior
 * y lleva el suyo; un fichero ancla (entries + head) detecta truncaciones,
 * borrados e inconsistencias internas del registro, incluidos los rollbacks
 * que rompen la cadena de checksums o el ancla esperada. Al abrir se
 * verifica TODO (cadena de hashes, checksums, secuencias estrictamente
 * monótonas, unicidad de la transición por (tipo, secuencia)) ANTES de
 * autorizar firma alguna. Corrupción, truncación, borrado o rollback
 * internamente inconsistente detectados = PARADA de firma con error
 * declarado; jamás reconstrucción silenciosa desde estado volátil.
 * Recuperación: solo desde snapshot autenticado + el log encadenado
 * posterior, verificados (ver restoreFromSnapshot).
 *
 * TESTIGO EXTERNO Y PRUEBA DE RECUPERACIÓN (R7-VOTE-RECOVERY, artefacto 13):
 * la verificación interna NO cubre por sí sola un rollback a un snapshot
 * íntegro y autocoherente del fichero o de la VM —registro y ancla
 * restaurados juntos y mutuamente consistentes—: ese estado es válido por
 * dentro y sin embargo más antiguo que votos ya autorizados. Por eso cada
 * registro tiene un TESTIGO EXTERNO: un registro de compromisos durable,
 * encadenado por MT-DUAL-1024 y con fsync, situado FUERA de la copia
 * restaurable del log (en esta topología local de testnet, un directorio
 * raíz de testigos por identidad —cadena, época, validador— fuera del
 * directorio del validador; ver voteLedgerWitnessPath). Cada entrada
 * duradera del WAL deja en el testigo un compromiso (secuencia duradera,
 * head, huella del estado anti-equivocación) ANTES de que la firma pueda
 * producirse. Al abrir, el estado recuperado se compara con el último
 * compromiso reconocido por el testigo y se emite la
 * VoteLedgerRecoveryProof del contrato de la Ronda 7 (§10 del documento
 * de consenso formal): si el estado recuperado es más antiguo que el
 * reconocido, si su huella no concuerda, o si la comparación no puede
 * hacerse (testigo ausente o ilegible), el resultado es
 * SIGNING_DISABLED / RECOVERY_REQUIRED (código VOTELEDGER_RECOVERY_REQUIRED)
 * y no se firma nada. Un WAL por DELANTE del testigo solo se acepta si el
 * estado en la secuencia reconocida coincide con el compromiso (el testigo
 * se pone al día de forma observable: catch-up verificado, nunca
 * reconstrucción del estado de votos). Si el propio testigo fuera
 * restaurado o borrado, la comparación falla y la firma queda
 * deshabilitada: fail-closed, nunca silencioso. Alcance honesto: en un
 * solo host el testigo protege frente a la restauración de la copia del
 * validador (directorio/VM del validador); un testigo en infraestructura
 * separada es la topología de producción (paso R7-HARDWARE), no este build.
 *
 * COMPACTACIÓN (MT-WAL-COMPACT-1, R7): el registro puede compactarse en
 * una base snapshot autenticada por su propio encadenado + compromiso en
 * el testigo registrado ANTES de podar, con la secuencia transaccional de
 * la especificación (archivar → persistir snapshot → registrar en el
 * testigo → construir y verificar la nueva base en fichero temporal →
 * activar por rename atómico → reanclar el piso del testigo). En ningún
 * instante falta una base anti-equivocación válida: un crash en cualquier
 * paso deja en pie la base antigua o la nueva, nunca un estado ambiguo
 * firmante (CON-17).
 *
 * CONCURRENCIA: varias instancias/procesos pueden compartir el registro
 * (p. ej. el modelo en-proceso y los procesos validadores de OPS-01 sobre
 * el mismo directorio). Toda mutación se hace bajo un cerrojo exclusivo
 * (fichero .lock con pid) y releyendo/verificando lo que otros hayan
 * añadido desde la última sincronización. EXCLUSIÓN MUTUA POR IDENTIDAD
 * (R7-X01): las operaciones de custodia toman además el cerrojo del
 * testigo de la identidad (orden fijo: testigo → WAL). Dos copias del
 * directorio de un validador en este host comparten el MISMO testigo por
 * identidad: la copia cuyo estado no coincide con el último compromiso
 * reconocido entra en RECOVERY_REQUIRED y no firma; la reconocida sigue
 * operando. Dos hosts sin un testigo común accesible no quedan cubiertos
 * por este mecanismo local (topología de producción, fuera de alcance).
 *
 * ALCANCE DECLARADO: esto es el build local de testnet. La topología de
 * producción (4 validadores en proveedores distintos, cada uno con SOLO su
 * registro) es el diseño declarado en MT-GATE-1/OPS-01, no este build: aquí
 * un ValidatorSet local custodia las 4 claves y abre un registro por
 * validador en el mismo directorio. Dinero real: BLOQUEADO.
 */
import { closeSync, copyFileSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, readdirSync, renameSync, rmSync, statSync, unlinkSync, writeSync, } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join } from "node:path";
import { canonicalBytes, canonicalize } from "./jcs.js";
import { mtDual1024, ZERO_HASH_1024 } from "./hash.js";
export const VOTELEDGER_FORMAT = "MT-VOTELEDGER-2";
export const VOTELEDGER_ANCHOR_FORMAT = "MT-VOTELEDGER-ANCHOR-1";
export const VOTELEDGER_SNAPSHOT_FORMAT = "MT-VOTELEDGER-SNAPSHOT-1";
export const VOTELEDGER_WITNESS_FORMAT = "MT-VOTELEDGER-WITNESS-1";
const VOTELEDGER_DOMAIN = "MT-VOTELEDGER-2";
const VOTELEDGER_STATE_DOMAIN = "MT-VOTELEDGER-2-STATE";
const VOTELEDGER_SNAPSHOT_DOMAIN = "MT-VOTELEDGER-2-SNAPSHOT";
const WITNESS_DOMAIN = "MT-VOTELEDGER-WITNESS-1";
export const VALIDATOR_SET_EPOCH_DOMAIN = "MT-VALIDATOR-SET-1";
/** Variable de entorno que fija la raíz de testigos (tests y despliegues). */
export const WITNESS_DIR_ENV = "MT_VOTELEDGER_WITNESS_DIR";
export class VoteLedgerCustodyError extends Error {
    code;
    /** Registro de equívoco cuando code === "VOTELEDGER_EQUIVOCATION". */
    equivocation;
    /** Prueba de recuperación cuando code === "VOTELEDGER_RECOVERY_REQUIRED". */
    recoveryProof;
    constructor(code, message, equivocation, recoveryProof) {
        super(message);
        this.code = code;
        this.name = "VoteLedgerCustodyError";
        this.equivocation = equivocation;
        this.recoveryProof = recoveryProof;
    }
}
function entryChecksum(e) {
    return mtDual1024(canonicalBytes(e), VOTELEDGER_DOMAIN);
}
function keyOf(kind, sequence) {
    return `${kind}|${sequence}`;
}
function sleepMs(ms) {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}
function fsyncDir(dir) {
    try {
        const fd = openSync(dir, "r");
        try {
            fsyncSync(fd);
        }
        finally {
            closeSync(fd);
        }
    }
    catch {
        /* mejor esfuerzo: hay plataformas que no permiten fsync de directorio */
    }
}
/**
 * Cerrojo exclusivo entre procesos sobre un fichero .lock con pid: espera
 * con límite, retira cerrojos de procesos muertos (o ilegibles/huérfanos) y
 * falla cerrado con VOTELEDGER_LOCK_TIMEOUT si el titular sigue vivo.
 * Lo comparten el WAL y el testigo de la identidad.
 */
function withFileLock(lockPath, fn) {
    const deadline = Date.now() + 15_000;
    let fd = null;
    for (;;) {
        try {
            fd = openSync(lockPath, "wx");
            writeSync(fd, JSON.stringify({ pid: process.pid, at: Date.now() }) + "\n", null, "utf8");
            break;
        }
        catch (err) {
            if (err.code !== "EEXIST")
                throw err;
            // Cerrojo existente: ¿vivo o resto de un proceso muerto (kill duro)?
            let stale = false;
            try {
                const info = JSON.parse(readFileSync(lockPath, "utf8"));
                let alive = false;
                try {
                    process.kill(info.pid, 0);
                    alive = true;
                }
                catch {
                    alive = false;
                }
                stale = !alive || Date.now() - info.at > 60_000;
            }
            catch {
                stale = true; // cerrojo ilegible: se trata como resto
            }
            if (stale) {
                try {
                    unlinkSync(lockPath);
                }
                catch {
                    /* otro proceso lo retiró primero */
                }
                continue;
            }
            if (Date.now() > deadline) {
                throw new VoteLedgerCustodyError("VOTELEDGER_LOCK_TIMEOUT", `Cerrojo ocupado >15 s en ${lockPath}; operación detenida`);
            }
            sleepMs(5);
        }
    }
    try {
        return fn();
    }
    finally {
        if (fd !== null) {
            try {
                closeSync(fd);
            }
            catch {
                /* ya cerrado */
            }
        }
        try {
            unlinkSync(lockPath);
        }
        catch {
            /* ya retirado */
        }
    }
}
// ---------------------------------------------------------------------------
// Testigo externo de la identidad (R7-VOTE-RECOVERY)
// ---------------------------------------------------------------------------
/** Raíz de testigos: opción explícita > entorno > ~/.million-tower-witness. */
export function voteLedgerWitnessRoot(options) {
    if (options?.witnessDir)
        return options.witnessDir;
    const env = process.env[WITNESS_DIR_ENV];
    if (env && env.length > 0)
        return env;
    return join(homedir(), ".million-tower-witness");
}
/** Directorio de testigos de una (cadena, época): lo retira el reseteo de
 *  un mundo testnet que se regenera por completo (fixture, nunca custodia). */
export function witnessEpochDir(chainId, epoch, options) {
    return join(voteLedgerWitnessRoot(options), chainId, epoch);
}
/**
 * Ruta del testigo de una identidad. Se deriva de la IDENTIDAD
 * (cadena, época del conjunto, validador), nunca de la ruta del WAL: dos
 * copias del directorio del validador en este host comparten el mismo
 * testigo, que es exactamente lo que exige la exclusión mutua R7-X01.
 */
export function voteLedgerWitnessPath(binding, options) {
    return join(witnessEpochDir(binding.chainId, binding.epoch, options), `${binding.validatorId}.witness.jsonl`);
}
/** Identificador estable del testigo de una identidad (campo del contrato). */
export function witnessIdFor(binding) {
    return `mt-voteledger-witness:${binding.chainId}:${binding.epoch}:${binding.validatorId}`;
}
/** Huella canónica de un núcleo de snapshot (campo snapshot_hash). */
export function snapshotFingerprint(core) {
    return mtDual1024(canonicalBytes(core), VOTELEDGER_SNAPSHOT_DOMAIN);
}
/**
 * Núcleo de snapshot «en el origen»: el snapshot que snapshotCore()
 * produciría sobre un registro recién creado (cubre solo la cabecera,
 * seq 0, sin votos). Es la base canónica de toda recuperación desde el
 * WAL completo sin snapshot — ver la decisión documentada en
 * INFORME-PQ-R7-recovery.md.
 */
export function emptySnapshotCore(binding, headerChecksum) {
    return {
        format: VOTELEDGER_SNAPSHOT_FORMAT,
        chain_id: binding.chainId,
        validator_id: binding.validatorId,
        epoch: binding.epoch,
        upto_entries: 0,
        head_hash: headerChecksum,
        votes: [],
    };
}
function witnessChecksum(e) {
    return mtDual1024(canonicalBytes(e), WITNESS_DOMAIN);
}
/**
 * Registro de compromisos de UNA identidad, fuera de la copia restaurable
 * del log de votos. Append-only, encadenado por MT-DUAL-1024, con fsync en
 * cada entrada. Su piso (último WITNESS_COMMIT/WITNESS_RESTORE) es la
 * referencia de continuidad contra la que se compara toda recuperación.
 * Las mutaciones exigen que el llamante tenga tomado el cerrojo del
 * testigo (DurableVoteLedger lo orquesta: orden fijo testigo → WAL) y
 * cada mutación RELEE y reverifica el fichero antes de añadir, para que
 * varias instancias de la misma identidad no operen sobre un piso
 * desactualizado.
 */
class VoteLedgerWitness {
    path;
    binding;
    lastSeq = 0;
    lastChecksum = ZERO_HASH_1024;
    floor = null;
    constructor(path, binding) {
        this.path = path;
        this.binding = binding;
    }
    /** Carga y VERIFICA el testigo completo (cadena, checksums, binding). */
    static load(path, binding) {
        const w = new VoteLedgerWitness(path, binding);
        w.reload();
        return w;
    }
    /** Crea el testigo con su cabecera (falla si ya existe). */
    static create(path, binding) {
        const w = new VoteLedgerWitness(path, binding);
        const core = {
            type: "WITNESS_HEADER",
            format: VOTELEDGER_WITNESS_FORMAT,
            chain_id: binding.chainId,
            validator_id: binding.validatorId,
            epoch: binding.epoch,
            seq: 0,
            prev_hash: ZERO_HASH_1024,
        };
        const full = { ...core, checksum: witnessChecksum(core) };
        const fd = openSync(path, "wx");
        try {
            writeSync(fd, canonicalize(full) + "\n", null, "utf8");
            fsyncSync(fd);
        }
        finally {
            closeSync(fd);
        }
        fsyncDir(dirname(path));
        w.lastSeq = 0;
        w.lastChecksum = full.checksum;
        return w;
    }
    /** Relee y reverifica el fichero; actualiza piso y cabeza en memoria. */
    reload() {
        const content = readFileSync(this.path, "utf8");
        const lines = content.split("\n");
        if (lines.length > 0 && lines[lines.length - 1] === "")
            lines.pop();
        if (lines.length === 0) {
            throw new VoteLedgerCustodyError("VOTELEDGER_WITNESS_CORRUPT", `Testigo ${this.path} vacío; no se puede comparar la continuidad: firma deshabilitada`);
        }
        let expectedPrev = ZERO_HASH_1024;
        let expectedSeq = 0;
        let floor = null;
        for (let i = 0; i < lines.length; i++) {
            let e;
            try {
                e = JSON.parse(lines[i]);
            }
            catch {
                throw new VoteLedgerCustodyError("VOTELEDGER_WITNESS_CORRUPT", `Testigo: la línea ${i + 1} no es JSON válido; firma deshabilitada`);
            }
            if (e.chain_id !== this.binding.chainId || e.validator_id !== this.binding.validatorId || e.epoch !== this.binding.epoch) {
                throw new VoteLedgerCustodyError("VOTELEDGER_BINDING_MISMATCH", `Testigo: la entrada ${i + 1} no pertenece a esta (cadena, validador, época); firma deshabilitada`);
            }
            if (e.seq !== expectedSeq || e.prev_hash !== expectedPrev) {
                throw new VoteLedgerCustodyError("VOTELEDGER_WITNESS_CORRUPT", `Testigo: encadenado o secuencia rotos en la línea ${i + 1}; firma deshabilitada`);
            }
            const { checksum, ...core } = e;
            if (witnessChecksum(core) !== checksum) {
                throw new VoteLedgerCustodyError("VOTELEDGER_WITNESS_CORRUPT", `Testigo: checksum inválido en la línea ${i + 1}; firma deshabilitada`);
            }
            if (i === 0 && (e.type !== "WITNESS_HEADER" || e.format !== VOTELEDGER_WITNESS_FORMAT)) {
                throw new VoteLedgerCustodyError("VOTELEDGER_WITNESS_CORRUPT", `Testigo: cabecera no reconocida; firma deshabilitada`);
            }
            if (e.type === "WITNESS_COMMIT" || e.type === "WITNESS_RESTORE") {
                floor = {
                    durable_sequence: e.durable_sequence,
                    wal_head_hash: e.wal_head_hash,
                    state_digest: e.state_digest,
                };
            }
            this.lastSeq = e.seq;
            this.lastChecksum = e.checksum;
            expectedPrev = e.checksum;
            expectedSeq = e.seq + 1;
        }
        this.floor = floor;
    }
    get floorState() {
        return this.floor;
    }
    /** Checksum de la última entrada del testigo (external_witness_hash). */
    get headChecksum() {
        return this.lastChecksum;
    }
    appendEntry(partial) {
        this.reload();
        const core = {
            ...partial,
            chain_id: this.binding.chainId,
            validator_id: this.binding.validatorId,
            epoch: this.binding.epoch,
            seq: this.lastSeq + 1,
            prev_hash: this.lastChecksum,
        };
        const full = { ...core, checksum: witnessChecksum(core) };
        try {
            const fd = openSync(this.path, "a");
            try {
                writeSync(fd, canonicalize(full) + "\n", null, "utf8");
                fsyncSync(fd);
            }
            finally {
                closeSync(fd);
            }
        }
        catch (err) {
            throw new VoteLedgerCustodyError("VOTELEDGER_WITNESS_WRITE_FAILED", `Testigo: la escritura duradera falló (${err instanceof Error ? err.message : String(err)}); firma BLOQUEADA`);
        }
        this.lastSeq = full.seq;
        this.lastChecksum = full.checksum;
        if (full.type === "WITNESS_COMMIT" || full.type === "WITNESS_RESTORE") {
            this.floor = {
                durable_sequence: full.durable_sequence,
                wal_head_hash: full.wal_head_hash,
                state_digest: full.state_digest,
            };
        }
        return full;
    }
    /**
     * Reconoce un nuevo compromiso de custodia (secuencia duradera, head y
     * huella del estado anti-equivocación). La secuencia reconocida NUNCA
     * retrocede: un compromiso igual al piso con el mismo contenido es un
     * no-op idempotente; cualquier otra cosa en o por debajo del piso es
     * divergencia → VOTELEDGER_RECOVERY_REQUIRED.
     */
    commit(c) {
        this.reload();
        const f = this.floor;
        if (f) {
            if (c.durable_sequence < f.durable_sequence) {
                throw new VoteLedgerCustodyError("VOTELEDGER_RECOVERY_REQUIRED", `Testigo: se intentó reconocer la secuencia ${c.durable_sequence}, por debajo del piso reconocido ${f.durable_sequence}; firma deshabilitada`);
            }
            if (c.durable_sequence === f.durable_sequence) {
                if (c.state_digest === f.state_digest && c.wal_head_hash === f.wal_head_hash)
                    return; // idempotente
                throw new VoteLedgerCustodyError("VOTELEDGER_RECOVERY_REQUIRED", `Testigo: compromiso divergente para la secuencia ya reconocida ${f.durable_sequence}; firma deshabilitada`);
            }
        }
        this.appendEntry({
            type: "WITNESS_COMMIT",
            durable_sequence: c.durable_sequence,
            wal_head_hash: c.wal_head_hash,
            state_digest: c.state_digest,
        });
    }
    /**
     * Registra el compromiso de un snapshot de compactación ANTES de podar
     * (paso 6 de MT-WAL-COMPACT-1). No mueve el piso: es la referencia que
     * permitirá distinguir la base nueva de una restauración anterior.
     */
    registerSnapshot(r) {
        this.reload();
        const f = this.floor;
        if (!f || f.durable_sequence !== r.upto_entries || f.wal_head_hash !== r.wal_head_hash) {
            throw new VoteLedgerCustodyError("VOTELEDGER_RECOVERY_REQUIRED", `Testigo: el compromiso de snapshot (seq ${r.upto_entries}) no coincide con el piso reconocido; compactación detenida`);
        }
        this.appendEntry({
            type: "WITNESS_SNAPSHOT",
            durable_sequence: r.upto_entries,
            wal_head_hash: r.wal_head_hash,
            snapshot_hash: r.snapshot_hash,
        });
    }
    /**
     * Reancla el piso a una REPRESENTACIÓN nueva del MISMO estado
     * (restauración verificada desde snapshot o activación de una base
     * compactada): misma secuencia duradera y misma huella de estado que el
     * piso, head nuevo. Si la representación ya es la reconocida, no-op.
     */
    registerRestore(r) {
        this.reload();
        const f = this.floor;
        if (!f) {
            if (r.from_head_hash !== ZERO_HASH_1024) {
                throw new VoteLedgerCustodyError("VOTELEDGER_RECOVERY_REQUIRED", `Testigo: reanclaje sin piso previo exige origen cero; firma deshabilitada`);
            }
            this.appendEntry({
                type: "WITNESS_RESTORE",
                durable_sequence: r.durable_sequence,
                wal_head_hash: r.wal_head_hash,
                state_digest: r.state_digest,
                snapshot_hash: r.snapshot_hash,
                from_head_hash: r.from_head_hash,
            });
            return;
        }
        if (r.durable_sequence !== f.durable_sequence || r.state_digest !== f.state_digest || r.from_head_hash !== f.wal_head_hash) {
            throw new VoteLedgerCustodyError("VOTELEDGER_RECOVERY_REQUIRED", `Testigo: el estado restaurado no es el reconocido (secuencia/huella/head no concuerdan); firma deshabilitada`);
        }
        if (r.wal_head_hash === f.wal_head_hash)
            return; // ya es la representación reconocida
        this.appendEntry({
            type: "WITNESS_RESTORE",
            durable_sequence: r.durable_sequence,
            wal_head_hash: r.wal_head_hash,
            state_digest: r.state_digest,
            snapshot_hash: r.snapshot_hash,
            from_head_hash: r.from_head_hash,
        });
    }
}
/**
 * Registro duradero de votos de UN validador, vinculado a (cadena, época
 * del conjunto). Es la única vía por la que la custodia autoriza firmas.
 */
export class DurableVoteLedger {
    filePath;
    binding;
    anchorPath;
    lockPath;
    hooks;
    votes = new Map();
    attempts = [];
    lastSeq = 0;
    lastChecksum = ZERO_HASH_1024;
    readOffset = 0; // bytes del fichero ya leídos y verificados
    halted = false;
    /** Veces que al abrir/sincronizar el ancla iba por detrás del log (crash
     *  entre el append y la actualización del ancla) y se re-ancló desde el
     *  propio log verificado. Observable: no es una reconstrucción silenciosa
     *  del estado de votos — el estado sale siempre del log duradero. */
    anchorRecoveries = 0;
    // --- Testigo externo y prueba de recuperación (R7) ---
    witnessPath = "";
    witnessLockPath = "";
    witness = null;
    witnessLockDepth = 0;
    /** Checksum de la cabecera del registro (base de snapshot en el origen). */
    headerChecksum = ZERO_HASH_1024;
    /** Núcleo de snapshot que sirvió de base a la recuperación de este
     *  registro: el de la entrada SNAPSHOT_STATE si la hay; si no, el núcleo
     *  «en el origen» (emptySnapshotCore). Fija snapshot_hash en la prueba. */
    baseSnapshotCore = null;
    /** Huella del estado capturada al pasar por la secuencia del piso del
     *  testigo durante la carga (verificación de ancestro en el catch-up). */
    digestAtFloorSeq = null;
    lastProof = null;
    /** MT-WAL-COMPACT-1 en curso: las autorizaciones de firma se detienen. */
    compacting = false;
    constructor(filePath, binding, hooks) {
        this.filePath = filePath;
        this.binding = binding;
        this.anchorPath = filePath + ".anchor.json";
        this.lockPath = filePath + ".lock";
        this.hooks = hooks;
    }
    /**
     * Abre (o crea) el registro y lo VERIFICA por completo antes de volver:
     * verificación interna (cadena, checksums, ancla) Y comparación de
     * continuidad contra el testigo externo de la identidad. Cualquier
     * inconsistencia lanza y ninguna firma quedará autorizada; un estado
     * recuperado más antiguo que el último compromiso reconocido por el
     * testigo —o imposible de comparar— lanza VOTELEDGER_RECOVERY_REQUIRED
     * con la VoteLedgerRecoveryProof adjunta (SIGNING_DISABLED).
     */
    static open(filePath, binding, hooks, options) {
        const ledger = new DurableVoteLedger(filePath, binding, hooks);
        ledger.witnessPath = voteLedgerWitnessPath(binding, options);
        ledger.witnessLockPath = ledger.witnessPath + ".lock";
        mkdirSync(dirname(ledger.witnessPath), { recursive: true });
        ledger.withWitnessLock(() => ledger.withLock(() => {
            ledger.cleanCompactTemps();
            if (!existsSync(filePath)) {
                if (existsSync(ledger.anchorPath)) {
                    throw new VoteLedgerCustodyError("VOTELEDGER_ROLLBACK_DETECTED", `El registro ${filePath} no existe pero su ancla sí: borrado o rollback detectado; firma detenida`);
                }
                if (existsSync(ledger.witnessPath)) {
                    throw new VoteLedgerCustodyError("VOTELEDGER_RECOVERY_REQUIRED", `El registro ${filePath} no existe pero su testigo externo reconoce estado de esta identidad: la copia restaurable desapareció; firma DESHABILITADA hasta completar la recuperación`);
                }
                ledger.createFresh();
                const w = VoteLedgerWitness.create(ledger.witnessPath, binding);
                ledger.witness = w;
                w.commit({
                    durable_sequence: 0,
                    wal_head_hash: ledger.lastChecksum,
                    state_digest: ledger.stateDigest(),
                });
                ledger.lastProof = ledger.buildProof(true, false, true);
                return;
            }
            // El testigo se carga primero: su piso fija la secuencia en la que
            // la carga del WAL debe capturar la huella de ancestro.
            let witness = null;
            if (existsSync(ledger.witnessPath)) {
                witness = VoteLedgerWitness.load(ledger.witnessPath, binding);
            }
            ledger.loadAndVerifyAll(witness?.floorState?.durable_sequence);
            ledger.checkAnchor(false);
            if (!witness || !witness.floorState) {
                ledger.witness = witness;
                const proof = ledger.buildProof(false, false, false);
                throw new VoteLedgerCustodyError("VOTELEDGER_RECOVERY_REQUIRED", `Registro de ${binding.validatorId}: no hay testigo externo con un compromiso reconocido contra el que comparar la recuperación (ausente o sin compromisos); firma DESHABILITADA (SIGNING_DISABLED / RECOVERY_REQUIRED)`, undefined, proof);
            }
            ledger.witness = witness;
            const floor = witness.floorState;
            let rollback = false;
            let why = "";
            if (floor.durable_sequence > ledger.lastSeq) {
                rollback = true;
                why = `el testigo reconoce la secuencia ${floor.durable_sequence} y el registro recuperado solo llega a ${ledger.lastSeq}: rollback a un estado anterior`;
            }
            else if (floor.durable_sequence === ledger.lastSeq && floor.state_digest !== ledger.stateDigest()) {
                rollback = true;
                why = `en la secuencia reconocida ${floor.durable_sequence} la huella del estado recuperado no concuerda con el compromiso del testigo: el estado no es el reconocido`;
            }
            else if (floor.durable_sequence < ledger.lastSeq && ledger.digestAtFloorSeq !== floor.state_digest) {
                rollback = true;
                why = `el estado del registro en la secuencia reconocida ${floor.durable_sequence} no concuerda con el compromiso del testigo: divergencia, no continuación`;
            }
            if (rollback) {
                const proof = ledger.buildProof(false, true, false);
                throw new VoteLedgerCustodyError("VOTELEDGER_RECOVERY_REQUIRED", `Registro de ${binding.validatorId}: ${why}; firma DESHABILITADA (SIGNING_DISABLED / RECOVERY_REQUIRED)`, undefined, proof);
            }
            if (floor.durable_sequence < ledger.lastSeq) {
                // Catch-up verificado: el WAL contiene el compromiso reconocido
                // como ancestro (huella capturada idéntica) y lo extiende; el
                // testigo se pone al día con el head ya verificado.
                witness.commit({
                    durable_sequence: ledger.lastSeq,
                    wal_head_hash: ledger.lastChecksum,
                    state_digest: ledger.stateDigest(),
                });
            }
            ledger.lastProof = ledger.buildProof(true, false, true);
        }));
        return ledger;
    }
    /** Construye la VoteLedgerRecoveryProof con el estado actual. */
    buildProof(signingEnabled, rollbackDetected, verified) {
        const base = this.baseSnapshotCore ?? emptySnapshotCore(this.binding, this.headerChecksum);
        return {
            validator_id: this.binding.validatorId,
            chain_id: this.binding.chainId,
            validator_epoch: this.binding.epoch,
            durable_sequence: this.lastSeq,
            wal_head_hash: this.lastChecksum,
            snapshot_hash: snapshotFingerprint(base),
            external_witness_id: witnessIdFor(this.binding),
            external_witness_sequence: this.witness?.floorState?.durable_sequence ?? 0,
            external_witness_hash: this.witness ? this.witness.headChecksum : ZERO_HASH_1024,
            restored_state_verified: verified,
            rollback_detected: rollbackDetected,
            signing_enabled: signingEnabled,
        };
    }
    /** La prueba de recuperación emitida al abrir (o tras compactar). */
    recoveryProof() {
        if (!this.lastProof) {
            throw new VoteLedgerCustodyError("VOTELEDGER_RECOVERY_REQUIRED", `Registro de ${this.binding.validatorId} sin prueba de recuperación: no fue abierto por la vía verificada`);
        }
        return this.lastProof;
    }
    /** Piso actual del testigo de esta identidad (observable para baterías). */
    witnessFloor() {
        return this.witness?.floorState ?? null;
    }
    /**
     * Inspección de recuperación SIN habilitar firma: carga WAL y testigo en
     * modo lectura (sin catch-up, sin crear nada, sin tocar el ancla) y
     * devuelve la VoteLedgerRecoveryProof resultante. signing_enabled solo
     * es true si la comparación completa pasa.
     */
    static inspectRecovery(filePath, binding, options) {
        const wp = voteLedgerWitnessPath(binding, options);
        let witness = null;
        if (existsSync(wp)) {
            try {
                witness = VoteLedgerWitness.load(wp, binding);
            }
            catch {
                witness = null; // testigo ilegible: no se puede comparar
            }
        }
        const ledger = new DurableVoteLedger(filePath, binding);
        ledger.witnessPath = wp;
        let walOk = false;
        if (existsSync(filePath)) {
            try {
                ledger.loadAndVerifyAll(witness?.floorState?.durable_sequence);
                walOk = true;
            }
            catch {
                walOk = false;
            }
        }
        const floor = witness?.floorState ?? null;
        let rollback = false;
        if (walOk && floor) {
            if (floor.durable_sequence > ledger.lastSeq)
                rollback = true;
            else if (floor.durable_sequence === ledger.lastSeq && floor.state_digest !== ledger.stateDigest())
                rollback = true;
            else if (floor.durable_sequence < ledger.lastSeq && ledger.digestAtFloorSeq !== floor.state_digest)
                rollback = true;
        }
        const verified = walOk && witness !== null && floor !== null && !rollback;
        if (!walOk) {
            return {
                validator_id: binding.validatorId,
                chain_id: binding.chainId,
                validator_epoch: binding.epoch,
                durable_sequence: 0,
                wal_head_hash: ZERO_HASH_1024,
                snapshot_hash: ZERO_HASH_1024,
                external_witness_id: witnessIdFor(binding),
                external_witness_sequence: floor?.durable_sequence ?? 0,
                external_witness_hash: witness ? witness.headChecksum : ZERO_HASH_1024,
                restored_state_verified: false,
                rollback_detected: rollback,
                signing_enabled: false,
            };
        }
        ledger.witness = witness;
        return ledger.buildProof(verified, rollback, verified);
    }
    // ------------------------------------------------------------------
    // Creación y carga verificada
    // ------------------------------------------------------------------
    createFresh() {
        const header = {
            type: "LEDGER_HEADER",
            format: VOTELEDGER_FORMAT,
            chain_id: this.binding.chainId,
            validator_id: this.binding.validatorId,
            epoch: this.binding.epoch,
            seq: 0,
            prev_hash: ZERO_HASH_1024,
        };
        const full = { ...header, checksum: entryChecksum(header) };
        const line = canonicalize(full) + "\n";
        const fd = openSync(this.filePath, "wx");
        try {
            writeSync(fd, line, null, "utf8");
            fsyncSync(fd);
        }
        finally {
            closeSync(fd);
        }
        fsyncDir(dirname(this.filePath));
        this.lastSeq = 0;
        this.lastChecksum = full.checksum;
        this.headerChecksum = full.checksum;
        this.readOffset = Buffer.byteLength(line, "utf8");
        this.writeAnchor();
        fsyncDir(dirname(this.filePath));
    }
    parseLine(raw, lineNo) {
        let obj;
        try {
            obj = JSON.parse(raw);
        }
        catch {
            throw new VoteLedgerCustodyError("VOTELEDGER_CORRUPT", `Registro ${this.filePath}: la línea ${lineNo} no es JSON válido (truncación o manipulación); firma detenida`);
        }
        if (typeof obj !== "object" || obj === null || Array.isArray(obj)) {
            throw new VoteLedgerCustodyError("VOTELEDGER_CORRUPT", `Registro: la línea ${lineNo} no es un objeto; firma detenida`);
        }
        return obj;
    }
    /** Huella canónica del estado anti-equivocación (mapa de votos). */
    static digestOfVotes(votes) {
        const all = [...votes.values()]
            .map((v) => ({ kind: v.kind, prev_state: v.prev_state, sequence: v.sequence, signature: v.signature, transition_hash: v.transition_hash }))
            .sort((a, b) => (keyOf(a.kind, a.sequence) < keyOf(b.kind, b.sequence) ? -1 : 1));
        return mtDual1024(canonicalBytes(all), VOTELEDGER_STATE_DOMAIN);
    }
    /**
     * Aplica una entrada ya verificada (checksum y encadenado) a unos
     * contenedores de estado dados. Es la ÚNICA semántica de aplicación:
     * la usan la carga, la sincronización, la predicción de la huella para
     * el compromiso del testigo y la verificación aislada de compactación.
     */
    static applyToState(votes, attempts, e) {
        if (e.type === "VOTE_COMMIT") {
            const key = keyOf(e.kind, e.sequence);
            if (votes.has(key)) {
                throw new VoteLedgerCustodyError("VOTELEDGER_CORRUPT", `Registro: doble compromiso para ${key} (seq ${e.seq}); firma detenida`);
            }
            votes.set(key, {
                kind: e.kind,
                sequence: e.sequence,
                prev_state: e.prev_state,
                transition_hash: e.transition_hash,
                signature: null,
            });
        }
        else if (e.type === "VOTE_SIGNATURE") {
            const key = keyOf(e.kind, e.sequence);
            const st = votes.get(key);
            if (!st || st.transition_hash !== e.transition_hash) {
                throw new VoteLedgerCustodyError("VOTELEDGER_CORRUPT", `Registro: firma sin compromiso coincidente para ${key} (seq ${e.seq}); firma detenida`);
            }
            if (st.signature !== null) {
                throw new VoteLedgerCustodyError("VOTELEDGER_CORRUPT", `Registro: segunda firma registrada para ${key} (seq ${e.seq}); firma detenida`);
            }
            st.signature = e.signature;
        }
        else if (e.type === "EQUIVOCATION_ATTEMPT") {
            const key = keyOf(e.kind, e.sequence);
            const st = votes.get(key);
            if (!st || st.transition_hash !== e.first_transition_hash) {
                throw new VoteLedgerCustodyError("VOTELEDGER_CORRUPT", `Registro: intento de equívoco sin primer voto coincidente para ${key} (seq ${e.seq}); firma detenida`);
            }
            attempts.push({
                validator_id: e.validator_id,
                chain_id: e.chain_id,
                kind: e.kind,
                sequence: e.sequence,
                first_transition_hash: e.first_transition_hash,
                conflicting_transition_hash: e.conflicting_transition_hash,
                evidence: "SECOND_SIGNATURE_ATTEMPT",
            });
        }
        else if (e.type === "SNAPSHOT_STATE") {
            const snap = e.snapshot;
            for (const v of snap.votes) {
                const key = keyOf(v.kind, v.sequence);
                if (votes.has(key)) {
                    throw new VoteLedgerCustodyError("VOTELEDGER_CORRUPT", `Registro: el snapshot repite ${key}; firma detenida`);
                }
                votes.set(key, { ...v });
            }
            if (e.attempts) {
                for (const a of e.attempts)
                    attempts.push({ ...a });
            }
        }
    }
    /** Aplica una entrada verificada al estado de esta instancia. */
    applyEntry(e) {
        DurableVoteLedger.applyToState(this.votes, this.attempts, e);
        if (e.type === "SNAPSHOT_STATE") {
            this.baseSnapshotCore = e.snapshot;
        }
        this.lastSeq = e.seq;
        this.lastChecksum = e.checksum;
    }
    verifyEntry(e, lineNo, expectedSeq, expectedPrev) {
        if (e.chain_id !== this.binding.chainId || e.validator_id !== this.binding.validatorId || e.epoch !== this.binding.epoch) {
            throw new VoteLedgerCustodyError("VOTELEDGER_BINDING_MISMATCH", `Registro: la entrada ${lineNo} no pertenece a (cadena=${this.binding.chainId}, validador=${this.binding.validatorId}, época=${this.binding.epoch}); firma detenida`);
        }
        if (e.seq !== expectedSeq) {
            throw new VoteLedgerCustodyError("VOTELEDGER_CORRUPT", `Registro: secuencia no monótona en la línea ${lineNo} (esperada ${expectedSeq}, leída ${e.seq}); firma detenida`);
        }
        if (e.prev_hash !== expectedPrev) {
            throw new VoteLedgerCustodyError("VOTELEDGER_CORRUPT", `Registro: encadenado roto en la línea ${lineNo} (prev_hash no coincide); firma detenida`);
        }
        const { checksum, ...core } = e;
        if (entryChecksum(core) !== checksum) {
            throw new VoteLedgerCustodyError("VOTELEDGER_CORRUPT", `Registro: checksum inválido en la línea ${lineNo}; firma detenida`);
        }
    }
    loadAndVerifyAll(floorSeq) {
        this.digestAtFloorSeq = null;
        const content = readFileSync(this.filePath, "utf8");
        const lines = content.split("\n");
        if (lines.length > 0 && lines[lines.length - 1] === "")
            lines.pop();
        if (lines.length === 0) {
            throw new VoteLedgerCustodyError("VOTELEDGER_CORRUPT", `Registro ${this.filePath} vacío; firma detenida`);
        }
        let offset = 0;
        let expectedPrev = ZERO_HASH_1024;
        let expectedSeq = 0;
        for (let i = 0; i < lines.length; i++) {
            const raw = lines[i];
            const e = this.parseLine(raw, i + 1);
            if (i === 0) {
                if (e.type !== "LEDGER_HEADER" || e.format !== VOTELEDGER_FORMAT) {
                    throw new VoteLedgerCustodyError("VOTELEDGER_CORRUPT", `Registro: cabecera no reconocida; firma detenida`);
                }
                this.verifyEntry(e, 1, 0, ZERO_HASH_1024);
                this.lastSeq = 0;
                this.lastChecksum = e.checksum;
                this.headerChecksum = e.checksum;
                if (floorSeq === 0)
                    this.digestAtFloorSeq = this.stateDigest();
                expectedPrev = e.checksum;
                expectedSeq = 1;
            }
            else {
                if (e.type === "SNAPSHOT_STATE") {
                    // La base restaurada declara su propio ancla de continuidad: su
                    // prev_hash debe ser el head_hash del snapshot autenticado, y su
                    // seq la de la última entrada cubierta por el snapshot.
                    const snap = e.snapshot;
                    if (!snap || e.prev_hash !== snap.head_hash || e.seq !== snap.upto_entries) {
                        throw new VoteLedgerCustodyError("VOTELEDGER_CORRUPT", `Registro: la base de snapshot no ancla con su contenido declarado (línea ${i + 1}); firma detenida`);
                    }
                    const { checksum, ...core } = e;
                    if (entryChecksum(core) !== checksum) {
                        throw new VoteLedgerCustodyError("VOTELEDGER_CORRUPT", `Registro: checksum inválido en la base de snapshot; firma detenida`);
                    }
                    if (e.chain_id !== this.binding.chainId || e.validator_id !== this.binding.validatorId || e.epoch !== this.binding.epoch) {
                        throw new VoteLedgerCustodyError("VOTELEDGER_BINDING_MISMATCH", `Registro: snapshot de otra (cadena, validador, época); firma detenida`);
                    }
                    this.applyEntry(e);
                    expectedPrev = e.checksum;
                    expectedSeq = e.seq + 1;
                }
                else {
                    this.verifyEntry(e, i + 1, expectedSeq, expectedPrev);
                    this.applyEntry(e);
                    expectedPrev = e.checksum;
                    expectedSeq = e.seq + 1;
                }
                if (floorSeq !== undefined && e.seq === floorSeq) {
                    // Huella del estado exactamente en la secuencia reconocida por
                    // el testigo: la prueba de ancestro para el catch-up verificado.
                    this.digestAtFloorSeq = this.stateDigest();
                }
            }
            offset += Buffer.byteLength(raw, "utf8") + 1;
        }
        this.readOffset = offset;
    }
    /** Relee lo añadido por otras instancias desde la última sincronización. */
    syncFromDisk() {
        const st = statSync(this.filePath);
        if (st.size === this.readOffset)
            return;
        if (st.size < this.readOffset) {
            throw new VoteLedgerCustodyError("VOTELEDGER_ROLLBACK_DETECTED", `Registro: el fichero se acortó (${this.readOffset} → ${st.size} bytes); firma detenida`);
        }
        const content = readFileSync(this.filePath, "utf8");
        // Se relee por bytes desde readOffset: los offsets se llevan en
        // bytes UTF-8 sobre el contenido completo ya decodificado.
        const buf = Buffer.from(content, "utf8");
        const newBytes = buf.subarray(this.readOffset);
        const newText = newBytes.toString("utf8");
        const lines = newText.split("\n");
        if (lines.length > 0 && lines[lines.length - 1] === "")
            lines.pop();
        let expectedPrev = this.lastChecksum;
        let expectedSeq = this.lastSeq + 1;
        for (let i = 0; i < lines.length; i++) {
            const e = this.parseLine(lines[i], -1);
            this.verifyEntry(e, -1, expectedSeq, expectedPrev);
            this.applyEntry(e);
            expectedPrev = e.checksum;
            expectedSeq = e.seq + 1;
            this.readOffset += Buffer.byteLength(lines[i], "utf8") + 1;
        }
    }
    // ------------------------------------------------------------------
    // Ancla anti-rollback
    // ------------------------------------------------------------------
    writeAnchor() {
        const anchor = {
            format: VOTELEDGER_ANCHOR_FORMAT,
            chain_id: this.binding.chainId,
            validator_id: this.binding.validatorId,
            epoch: this.binding.epoch,
            entries: this.lastSeq,
            head: this.lastChecksum,
        };
        const tmp = `${this.anchorPath}.tmp-${process.pid}`;
        const fd = openSync(tmp, "w");
        try {
            writeSync(fd, JSON.stringify(anchor) + "\n", null, "utf8");
            fsyncSync(fd);
        }
        finally {
            closeSync(fd);
        }
        renameSync(tmp, this.anchorPath);
    }
    checkAnchor(fromSync) {
        if (!existsSync(this.anchorPath)) {
            throw new VoteLedgerCustodyError("VOTELEDGER_CORRUPT", `Registro: falta el fichero ancla ${this.anchorPath}; firma detenida`);
        }
        let anchor;
        try {
            anchor = JSON.parse(readFileSync(this.anchorPath, "utf8"));
        }
        catch {
            throw new VoteLedgerCustodyError("VOTELEDGER_CORRUPT", `Registro: ancla ilegible; firma detenida`);
        }
        if (anchor.format !== VOTELEDGER_ANCHOR_FORMAT ||
            anchor.chain_id !== this.binding.chainId ||
            anchor.validator_id !== this.binding.validatorId ||
            anchor.epoch !== this.binding.epoch) {
            throw new VoteLedgerCustodyError("VOTELEDGER_BINDING_MISMATCH", `Registro: el ancla no pertenece a esta (cadena, validador, época); firma detenida`);
        }
        if (anchor.entries > this.lastSeq) {
            throw new VoteLedgerCustodyError("VOTELEDGER_ROLLBACK_DETECTED", `Registro: el ancla declara ${anchor.entries} entradas y el log tiene ${this.lastSeq}: rollback o borrado detectado; firma detenida`);
        }
        if (anchor.entries === this.lastSeq && anchor.head !== this.lastChecksum) {
            throw new VoteLedgerCustodyError("VOTELEDGER_CORRUPT", `Registro: la cabeza del log no coincide con el ancla; firma detenida`);
        }
        if (anchor.entries < this.lastSeq) {
            // Crash entre el append (fsync hecho) y la actualización del ancla:
            // el LOG verificado manda; se re-ancla y queda constancia observable.
            if (!fromSync)
                this.anchorRecoveries++;
            this.writeAnchor();
        }
    }
    // ------------------------------------------------------------------
    // Cerrojos exclusivos entre procesos/instancias
    // ------------------------------------------------------------------
    /** Cerrojo del WAL de este registro. */
    withLock(fn) {
        return withFileLock(this.lockPath, fn);
    }
    /**
     * Cerrojo del TESTIGO de la identidad (R7-X01). Orden de adquisición
     * fijo en toda la custodia: primero el testigo, después el WAL — así,
     * dos instancias de la misma identidad (incluidas dos copias del
     * directorio en este host) se serializan sobre el estado reconocido
     * común antes de tocar su copia local. Reentrante por contador para
     * que las operaciones internas no se autobloqueen.
     */
    withWitnessLock(fn) {
        if (this.witnessLockDepth > 0) {
            this.witnessLockDepth++;
            try {
                return fn();
            }
            finally {
                this.witnessLockDepth--;
            }
        }
        this.witnessLockDepth = 1;
        try {
            return withFileLock(this.witnessLockPath, fn);
        }
        finally {
            this.witnessLockDepth = 0;
        }
    }
    /**
     * Deja un compromiso en el testigo para una entrada del WAL ya
     * persistida. Exige el cerrojo del testigo tomado (lo toman las
     * operaciones públicas); sin él, lo toma aquí. Si el testigo no puede
     * escribir, la custodia se detiene y la operación aborta ANTES de
     * firmar: la entrada del WAL queda duradera y el testigo se pondrá al
     * día en la próxima apertura verificada (catch-up), pero ninguna firma
     * sale de una custodia cuyo compromiso externo no se pudo registrar.
     */
    /**
     * Compuerta de alineación con el testigo (A7 · F-A7-01): TODA operación
     * de custodia que pueda appendar (prepareVote / persistSignature)
     * verifica ANTES de tocar el WAL, bajo los cerrojos testigo → WAL y tras
     * sincronizar desde disco, que el estado local ES exactamente el último
     * compromiso reconocido por el testigo externo (secuencia, head y
     * huella). Sin esta compuerta, una instancia viva cuya copia quedó
     * atrás (otra instancia de la misma identidad avanzó el piso) appendaba
     * entradas que el testigo rechazaba una a una —el WAL local crecía con
     * entradas no reconocidas— hasta que su secuencia superaba la del piso
     * y `commit()` aceptaba el salto sin comprobación de ancestro: el piso
     * pasaba a la línea divergente, la firma incompatible quedaba liberable
     * por la vía idempotente y la copia reconocida quedaba bloqueada
     * (reproducido contra el código en la exploración A7; la vertiente de
     * CON-16 solo cubría la copia que REABRE tras divergir). Con la
     * compuerta, la copia atrasada o divergente se detiene en
     * RECOVERY_REQUIRED antes de appendar nada: no firma, no infla su
     * secuencia y no puede capturar el piso; la copia reconocida sigue
     * operando. La reapertura verificada (open) sigue siendo la única vía
     * de recuperación.
     */
    assertWitnessFloorAligned() {
        const witness = this.witness;
        if (!witness) {
            throw new VoteLedgerCustodyError("VOTELEDGER_RECOVERY_REQUIRED", `Custodia de ${this.binding.validatorId}: sin testigo externo la continuidad no puede verificarse; firma DESHABILITADA (SIGNING_DISABLED / RECOVERY_REQUIRED)`);
        }
        try {
            witness.reload();
        }
        catch (err) {
            if (err instanceof VoteLedgerCustodyError)
                throw err;
            throw new VoteLedgerCustodyError("VOTELEDGER_RECOVERY_REQUIRED", `Custodia de ${this.binding.validatorId}: el testigo externo no puede releerse (${err instanceof Error ? err.message : String(err)}); firma DESHABILITADA (SIGNING_DISABLED / RECOVERY_REQUIRED)`);
        }
        const floor = witness.floorState;
        if (!floor ||
            floor.durable_sequence !== this.lastSeq ||
            floor.wal_head_hash !== this.lastChecksum ||
            floor.state_digest !== this.stateDigest()) {
            throw new VoteLedgerCustodyError("VOTELEDGER_RECOVERY_REQUIRED", `Custodia de ${this.binding.validatorId}: el estado local (secuencia ${this.lastSeq}) no es el último compromiso reconocido por el testigo externo (secuencia ${floor?.durable_sequence ?? "sin compromiso"}): otra instancia avanzó el estado reconocido o esta copia divergió; firma DESHABILITADA hasta completar la recuperación por la vía de apertura verificada`);
        }
    }
    witnessCommit(full, digestAfter) {
        if (!this.witness)
            return;
        const doCommit = () => {
            try {
                this.witness.commit({
                    durable_sequence: full.seq,
                    wal_head_hash: full.checksum,
                    state_digest: digestAfter,
                });
            }
            catch (err) {
                if (err instanceof VoteLedgerCustodyError && err.code === "VOTELEDGER_RECOVERY_REQUIRED")
                    throw err;
                this.halted = true;
                throw new VoteLedgerCustodyError("VOTELEDGER_FSYNC_FAILED", `Registro: el compromiso en el testigo externo falló (${err instanceof Error ? err.message : String(err)}); firma BLOQUEADA y custodia detenida`);
            }
        };
        if (this.witnessLockDepth > 0)
            doCommit();
        else
            this.withWitnessLock(doCommit);
    }
    /** Retira temporales de compactación interrumpidas (inertes: la base
     *  válida es siempre el fichero del registro o su sucesor activado). */
    cleanCompactTemps() {
        try {
            const dir = dirname(this.filePath);
            const prefix = basename(this.filePath) + ".compact-tmp-";
            for (const name of readdirSync(dir)) {
                if (name.startsWith(prefix)) {
                    try {
                        unlinkSync(join(dir, name));
                    }
                    catch {
                        /* mejor esfuerzo */
                    }
                }
            }
        }
        catch {
            /* el directorio siempre existe en la práctica */
        }
    }
    // ------------------------------------------------------------------
    // Append duradero (la única escritura que existe)
    // ------------------------------------------------------------------
    appendEntry(partial) {
        const core = {
            ...partial,
            chain_id: this.binding.chainId,
            validator_id: this.binding.validatorId,
            epoch: this.binding.epoch,
            seq: this.lastSeq + 1,
            prev_hash: this.lastChecksum,
        };
        const full = { ...core, checksum: entryChecksum(core) };
        const line = canonicalize(full) + "\n";
        // Huella del estado DESPUÉS de aplicar esta entrada, predicha sobre
        // una copia del mapa: es el compromiso que el testigo reconocerá por
        // esta entrada. (Los llamantes aplican la entrada al mapa real tras
        // el append; la predicción usa la misma semántica applyToState.)
        let digestAfter = null;
        if (this.witness) {
            // Copia profunda de los estados: la sonda no debe tocar el mapa real
            // (la entrada aún no es duradera cuando se predice su huella).
            const probe = new Map([...this.votes].map(([k, v]) => [k, { ...v }]));
            const probeAttempts = [];
            DurableVoteLedger.applyToState(probe, probeAttempts, full);
            digestAfter = DurableVoteLedger.digestOfVotes(probe);
        }
        let fd;
        try {
            fd = openSync(this.filePath, "a");
            try {
                writeSync(fd, line, null, "utf8");
                fsyncSync(fd);
            }
            finally {
                closeSync(fd);
            }
        }
        catch (err) {
            this.halted = true;
            throw new VoteLedgerCustodyError("VOTELEDGER_FSYNC_FAILED", `Registro: la escritura duradera falló (${err instanceof Error ? err.message : String(err)}); firma BLOQUEADA y custodia detenida`);
        }
        this.lastSeq = full.seq;
        this.lastChecksum = full.checksum;
        this.readOffset += Buffer.byteLength(line, "utf8");
        try {
            this.writeAnchor();
        }
        catch (err) {
            // La entrada SÍ está persistida y fsyncada; el ancla se re-sincroniza
            // en la próxima apertura (queda constancia en anchorRecoveries).
            void err;
        }
        // Compromiso en el testigo externo: DESPUÉS del fsync del WAL y ANTES
        // de que el llamante pueda firmar (el pipeline firma aguas abajo).
        if (this.witness && digestAfter !== null) {
            this.witnessCommit(full, digestAfter);
        }
        return full;
    }
    // ------------------------------------------------------------------
    // API de custodia (pipeline MT-VOTELEDGER-2)
    // ------------------------------------------------------------------
    get isHalted() {
        return this.halted;
    }
    /** Huella ya votada por este registro para la transición, si existe. */
    recordedHash(d) {
        return this.votes.get(keyOf(d.kind, d.sequence))?.transition_hash;
    }
    /** Firma ya registrada para la transición idéntica, si existe. */
    recordedSignature(d) {
        const st = this.votes.get(keyOf(d.kind, d.sequence));
        return st && st.transition_hash === d.transition_hash ? (st.signature ?? undefined) : undefined;
    }
    equivocationAttempts() {
        return this.attempts;
    }
    headInfo() {
        return { entries: this.lastSeq, head: this.lastChecksum };
    }
    /** Huella del estado anti-equivocación completo (para comparar restauraciones). */
    stateDigest() {
        return DurableVoteLedger.digestOfVotes(this.votes);
    }
    assertBinding(d) {
        if (d.chain_id !== this.binding.chainId) {
            throw new VoteLedgerCustodyError("VOTELEDGER_BINDING_MISMATCH", `Custodia de ${this.binding.validatorId}: la transición es de la cadena ${d.chain_id} y este registro es de ${this.binding.chainId}; firma detenida`);
        }
    }
    /**
     * Pasos (i)–(iii) del pipeline: valida la petición contra el estado
     * duradero y, si es un voto nuevo, persiste su compromiso con fsync
     * ANTES de que el llamante pueda firmar. Devuelve:
     *  - { status: "signed", signature } si la transición idéntica ya tiene
     *    firma registrada (entrega idempotente de la MISMA firma);
     *  - { status: "committed" } si el compromiso ya está duradero y el
     *    llamante puede firmar ahora (y debe persistir la firma con
     *    persistSignature ANTES de entregarla).
     * Un voto conflictivo se registra como intento de equivocación duradero
     * y se rechaza con VOTELEDGER_EQUIVOCATION.
     * La operación completa se ejecuta bajo el cerrojo del testigo de la
     * identidad (R7-X01): ninguna otra instancia de la misma identidad
     * puede intercalar un compromiso entre la validación y el registro.
     */
    prepareVote(d) {
        if (this.compacting) {
            throw new VoteLedgerCustodyError("VOTELEDGER_COMPACTION_IN_PROGRESS", `Custodia de ${this.binding.validatorId}: compactación en curso; autorizaciones de firma detenidas (MT-WAL-COMPACT-1)`);
        }
        return this.withWitnessLock(() => this.prepareVoteInner(d));
    }
    prepareVoteInner(d) {
        if (this.halted) {
            throw new VoteLedgerCustodyError("VOTELEDGER_HALTED", `Custodia de ${this.binding.validatorId} detenida por un fallo previo; firma bloqueada`);
        }
        this.assertBinding(d);
        let freshCommit = false;
        const result = this.withLock(() => {
            this.syncFromDisk();
            this.checkAnchor(true);
            this.assertWitnessFloorAligned();
            const key = keyOf(d.kind, d.sequence);
            const st = this.votes.get(key);
            if (st) {
                if (st.transition_hash !== d.transition_hash) {
                    const record = {
                        validator_id: this.binding.validatorId,
                        chain_id: d.chain_id,
                        kind: d.kind,
                        sequence: d.sequence,
                        first_transition_hash: st.transition_hash,
                        conflicting_transition_hash: d.transition_hash,
                        evidence: "SECOND_SIGNATURE_ATTEMPT",
                    };
                    this.appendEntry({
                        type: "EQUIVOCATION_ATTEMPT",
                        kind: d.kind,
                        sequence: d.sequence,
                        first_transition_hash: st.transition_hash,
                        conflicting_transition_hash: d.transition_hash,
                    });
                    this.attempts.push(record);
                    throw new VoteLedgerCustodyError("VOTELEDGER_EQUIVOCATION", `${this.binding.validatorId} ya votó otra transición para ${d.kind}#${d.sequence}: segunda firma rechazada y equívoco registrado en el registro duradero`, record);
                }
                if (st.signature !== null) {
                    return { status: "signed", signature: st.signature };
                }
                return { status: "committed" }; // crash previo entre compromiso y firma: se reanuda
            }
            const entry = this.appendEntry({
                type: "VOTE_COMMIT",
                kind: d.kind,
                sequence: d.sequence,
                prev_state: d.prev_state,
                transition_hash: d.transition_hash,
            });
            this.votes.set(key, {
                kind: d.kind,
                sequence: d.sequence,
                prev_state: d.prev_state,
                transition_hash: d.transition_hash,
                signature: null,
            });
            void entry;
            freshCommit = true;
            return { status: "committed" };
        });
        if (freshCommit && this.hooks?.afterCommitFsync) {
            this.hooks.afterCommitFsync({ transition: d });
        }
        return result;
    }
    /**
     * Paso (iv) del pipeline: persiste la firma emitida (append + fsync)
     * ANTES de que el llamante la entregue. Si la escritura falla, lanza
     * VOTELEDGER_FSYNC_FAILED y la firma producida debe DESCARTARSE.
     * Como prepareVote, se ejecuta bajo el cerrojo del testigo (R7-X01).
     */
    persistSignature(d, signature) {
        if (this.compacting) {
            throw new VoteLedgerCustodyError("VOTELEDGER_COMPACTION_IN_PROGRESS", `Custodia de ${this.binding.validatorId}: compactación en curso; autorizaciones de firma detenidas (MT-WAL-COMPACT-1)`);
        }
        return this.withWitnessLock(() => this.persistSignatureInner(d, signature));
    }
    persistSignatureInner(d, signature) {
        if (this.halted) {
            throw new VoteLedgerCustodyError("VOTELEDGER_HALTED", `Custodia de ${this.binding.validatorId} detenida por un fallo previo; firma bloqueada`);
        }
        this.assertBinding(d);
        this.withLock(() => {
            this.syncFromDisk();
            this.checkAnchor(true);
            this.assertWitnessFloorAligned();
            const key = keyOf(d.kind, d.sequence);
            const st = this.votes.get(key);
            if (!st || st.transition_hash !== d.transition_hash) {
                this.halted = true;
                throw new VoteLedgerCustodyError("VOTELEDGER_CORRUPT", `Custodia: se intentó persistir una firma sin compromiso coincidente para ${key}; custodia detenida`);
            }
            if (st.signature !== null) {
                if (st.signature === signature)
                    return; // idempotente
                this.halted = true;
                throw new VoteLedgerCustodyError("VOTELEDGER_CORRUPT", `Custodia: ya existe OTRA firma registrada para ${key}; una segunda firma distinta jamás se persiste`);
            }
            this.appendEntry({
                type: "VOTE_SIGNATURE",
                kind: d.kind,
                sequence: d.sequence,
                transition_hash: d.transition_hash,
                signature,
            });
            st.signature = signature;
        });
        if (this.hooks?.afterSignatureFsync) {
            this.hooks.afterSignatureFsync({ transition: d });
        }
    }
    // ------------------------------------------------------------------
    // MT-WAL-COMPACT-1 — compactación segura del registro (R7)
    // ------------------------------------------------------------------
    /** Verifica un fichero de registro de forma aislada (solo lectura):
     *  devuelve (entradas, head, huella del estado) o lanza si no verifica. */
    static verifyFileState(path, binding) {
        const probe = new DurableVoteLedger(path, binding);
        probe.loadAndVerifyAll();
        return { entries: probe.lastSeq, head: probe.lastChecksum, digest: probe.stateDigest() };
    }
    /**
     * Compacta el registro a una base snapshot (MT-WAL-COMPACT-1, §11 del
     * documento de consenso formal), con la secuencia obligatoria:
     *  (1) detener nuevas autorizaciones (flag + cerrojos testigo → WAL);
     *  (2) sincronizar el WAL; (3) construir el snapshot del estado
     *  anti-equivocación completo; (4) verificarlo contra una relectura
     *  aislada del WAL completo; (5) archivar la evidencia histórica
     *  (copia íntegra) y persistir el snapshot con fsync; (6) registrar su
     *  compromiso en el testigo externo ANTES de podar; (7) construir la
     *  nueva base en un fichero temporal; (8) verificarla en aislamiento
     *  (misma huella de estado, mismo punto de corte); (9) activarla por
     *  rename atómico y reescribir el ancla; (10) reanclar el piso del
     *  testigo a la nueva base (mismo estado, nueva representación);
     *  (11) reanudar la firma desde la base verificada.
     * Invariante de no-vacío: un crash antes del rename deja intacta la
     * base antigua; un crash después deja la nueva base completa con su
     * compromiso externo; nunca existe un instante firmando desde un
     * estado ambiguo (CON-17 inyecta el crash en cada paso).
     */
    compact(hooks) {
        if (this.halted) {
            throw new VoteLedgerCustodyError("VOTELEDGER_HALTED", `Custodia de ${this.binding.validatorId} detenida por un fallo previo; compactación bloqueada`);
        }
        const witness = this.witness;
        if (!witness) {
            throw new VoteLedgerCustodyError("VOTELEDGER_RECOVERY_REQUIRED", `Custodia de ${this.binding.validatorId}: sin testigo externo no hay compactación segura (el compromiso previo a la poda no podría registrarse)`);
        }
        return this.withWitnessLock(() => this.withLock(() => {
            if (this.compacting) {
                throw new VoteLedgerCustodyError("VOTELEDGER_COMPACTION_IN_PROGRESS", `Custodia de ${this.binding.validatorId}: ya hay una compactación en curso`);
            }
            this.compacting = true;
            try {
                // (1)+(2): el flag detiene prepareVote/persistSignature durante
                // toda la operación y los cerrojos serializan a otras instancias.
                this.syncFromDisk();
                this.checkAnchor(true);
                witness.reload();
                const floor = witness.floorState;
                if (!floor || floor.durable_sequence !== this.lastSeq || floor.state_digest !== this.stateDigest()) {
                    throw new VoteLedgerCustodyError("VOTELEDGER_RECOVERY_REQUIRED", `Custodia de ${this.binding.validatorId}: el piso del testigo no está alineado con el WAL; compactación detenida`);
                }
                // (3) Snapshot del estado completo en el punto de corte actual.
                const core = this.snapshotCore();
                const fp = snapshotFingerprint(core);
                // (4) Verificación contra el WAL completo, releído en aislamiento.
                const check = DurableVoteLedger.verifyFileState(this.filePath, this.binding);
                if (check.entries !== this.lastSeq || check.head !== this.lastChecksum || check.digest !== this.stateDigest()) {
                    throw new VoteLedgerCustodyError("VOTELEDGER_CORRUPT", `Custodia de ${this.binding.validatorId}: el snapshot no concuerda con la relectura completa del WAL; compactación detenida sin podar nada`);
                }
                // (5) Archivo de la evidencia histórica (copia íntegra del WAL
                // previo) y snapshot persistido. Todavía no se poda nada.
                // Observación de H-A8-09, adjudicada por la casa (SE ARREGLA):
                // una compactación repetida al MISMO upto sobrescribía el
                // archivo forense previo y la copia del WAL pre-compactación
                // se perdía. Ninguna evidencia forense se sobrescribe en
                // silencio en esta casa: si el nombre canónico ya existe, el
                // archivo nuevo va a un nombre único derivado DENTRO del mismo
                // formato (.archive-<upto>-2.jsonl, -3, …) — las herramientas
                // que buscan por el prefijo «.archive-» y el sufijo «.jsonl»
                // lo siguen encontrando, y el archivo previo queda intacto.
                // (Se descartó rechazar con error: la compactación doble sin
                // votos entre medias es un flujo legítimo — battery22
                // H09-CP-02 — y no debe lanzar.)
                let archivePath = `${this.filePath}.archive-${core.upto_entries}.jsonl`;
                for (let n = 2; existsSync(archivePath); n++) {
                    archivePath = `${this.filePath}.archive-${core.upto_entries}-${n}.jsonl`;
                }
                const archTmp = `${archivePath}.tmp-${process.pid}`;
                copyFileSync(this.filePath, archTmp);
                {
                    const fd = openSync(archTmp, "r");
                    try {
                        fsyncSync(fd);
                    }
                    finally {
                        closeSync(fd);
                    }
                }
                renameSync(archTmp, archivePath);
                if (existsSync(this.anchorPath)) {
                    copyFileSync(this.anchorPath, `${archivePath}.anchor.json`);
                }
                fsyncDir(dirname(this.filePath));
                hooks?.afterArchive?.();
                const snapPath = this.filePath + ".snapshot.json";
                const snapTmp = `${snapPath}.tmp-${process.pid}`;
                {
                    const fd = openSync(snapTmp, "w");
                    try {
                        writeSync(fd, canonicalize({ core, snapshot_hash: fp }) + "\n", null, "utf8");
                        fsyncSync(fd);
                    }
                    finally {
                        closeSync(fd);
                    }
                }
                renameSync(snapTmp, snapPath);
                fsyncDir(dirname(this.filePath));
                hooks?.afterSnapshotPersisted?.();
                // (6) Compromiso del snapshot en el testigo externo, ANTES de podar.
                witness.registerSnapshot({ snapshot_hash: fp, upto_entries: core.upto_entries, wal_head_hash: core.head_hash });
                hooks?.afterWitnessRegistered?.();
                // (7) Nueva base en fichero temporal: cabecera + SNAPSHOT_STATE
                // con el estado completo (votos, firmas y evidencia de intentos).
                const headerCore = {
                    type: "LEDGER_HEADER",
                    format: VOTELEDGER_FORMAT,
                    chain_id: this.binding.chainId,
                    validator_id: this.binding.validatorId,
                    epoch: this.binding.epoch,
                    seq: 0,
                    prev_hash: ZERO_HASH_1024,
                };
                const headerFull = { ...headerCore, checksum: entryChecksum(headerCore) };
                const baseCore = {
                    type: "SNAPSHOT_STATE",
                    chain_id: this.binding.chainId,
                    validator_id: this.binding.validatorId,
                    epoch: this.binding.epoch,
                    seq: core.upto_entries,
                    prev_hash: core.head_hash,
                    snapshot: core,
                    ...(this.attempts.length > 0 ? { attempts: this.attempts.map((a) => ({ ...a })) } : {}),
                };
                const baseFull = { ...baseCore, checksum: entryChecksum(baseCore) };
                const l1 = canonicalize(headerFull) + "\n";
                const l2 = canonicalize(baseFull) + "\n";
                const tmpPath = `${this.filePath}.compact-tmp-${process.pid}`;
                {
                    const fd = openSync(tmpPath, "w");
                    try {
                        writeSync(fd, l1, null, "utf8");
                        writeSync(fd, l2, null, "utf8");
                        fsyncSync(fd);
                    }
                    finally {
                        closeSync(fd);
                    }
                }
                fsyncDir(dirname(this.filePath));
                // (8) Verificación aislada de la nueva base: mismo punto de
                // corte y MISMA huella de estado anti-equivocación.
                const v = DurableVoteLedger.verifyFileState(tmpPath, this.binding);
                if (v.entries !== core.upto_entries || v.head !== baseFull.checksum || v.digest !== this.stateDigest()) {
                    throw new VoteLedgerCustodyError("VOTELEDGER_CORRUPT", `Custodia de ${this.binding.validatorId}: la nueva base no reproduce el estado verificado; compactación detenida sin podar nada`);
                }
                hooks?.afterNewBaseVerified?.();
                // (9)+(10) Activación atómica y reanclaje del piso del testigo
                // a la nueva representación del mismo estado.
                renameSync(tmpPath, this.filePath);
                this.lastSeq = core.upto_entries;
                this.lastChecksum = baseFull.checksum;
                this.readOffset = Buffer.byteLength(l1, "utf8") + Buffer.byteLength(l2, "utf8");
                this.baseSnapshotCore = core;
                this.writeAnchor();
                fsyncDir(dirname(this.filePath));
                witness.registerRestore({
                    snapshot_hash: fp,
                    durable_sequence: core.upto_entries,
                    wal_head_hash: baseFull.checksum,
                    state_digest: this.stateDigest(),
                    from_head_hash: core.head_hash,
                });
                this.lastProof = this.buildProof(true, false, true);
                hooks?.afterActivated?.();
                // (11) La firma se reanuda al salir (flag liberado en finally).
                return { snapshot_hash: fp, upto_entries: core.upto_entries, archived_to: archivePath };
            }
            finally {
                this.compacting = false;
            }
        }));
    }
    // ------------------------------------------------------------------
    // Snapshot autenticado + restauración verificada (CON-13)
    // ------------------------------------------------------------------
    /** Núcleo del snapshot del estado actual (la firma la pone la custodia). */
    snapshotCore() {
        const votes = [...this.votes.values()]
            .map((v) => ({ ...v }))
            .sort((a, b) => (keyOf(a.kind, a.sequence) < keyOf(b.kind, b.sequence) ? -1 : 1));
        return {
            format: VOTELEDGER_SNAPSHOT_FORMAT,
            chain_id: this.binding.chainId,
            validator_id: this.binding.validatorId,
            epoch: this.binding.epoch,
            upto_entries: this.lastSeq,
            head_hash: this.lastChecksum,
            votes,
        };
    }
    /** Líneas crudas (sin la cabecera) de las entradas con seq > afterSeq. */
    exportTailLines(afterSeq) {
        const content = readFileSync(this.filePath, "utf8");
        const lines = content.split("\n");
        if (lines.length > 0 && lines[lines.length - 1] === "")
            lines.pop();
        const out = [];
        for (let i = 1; i < lines.length; i++) {
            const e = JSON.parse(lines[i]);
            if (e.seq > afterSeq)
                out.push(lines[i]);
        }
        return out;
    }
    /**
     * Restaura un registro desde un snapshot AUTENTICADO (la verificación de
     * la firma la hace `verifyAuth` contra la clave pública del manifiesto)
     * más el log encadenado posterior al snapshot. Cada línea posterior se
     * verifica (checksum, encadenado desde head_hash del snapshot, binding)
     * antes de aplicarse. El estado resultante es el del registro original.
     *
     * R7: la restauración también se reconcilia con el testigo externo de
     * la identidad ANTES de habilitar firma alguna. Si ya existe un testigo
     * con un compromiso reconocido, el estado restaurado debe ser ESE
     * estado (misma secuencia duradera y misma huella): el testigo reancla
     * su piso a la nueva representación (WITNESS_RESTORE). Restaurar un
     * estado más antiguo que el reconocido —o uno divergente— se rechaza
     * con VOTELEDGER_RECOVERY_REQUIRED y el fichero recién construido se
     * retira: una restauración nunca puede convertirse en un rollback.
     * Sin testigo previo, la restauración ancla el primero (génesis de la
     * continuidad para esa identidad).
     */
    static restoreFromSnapshot(filePath, binding, snapshot, snapshotSignature, verifyAuth, tailLines, options) {
        if (snapshot.format !== VOTELEDGER_SNAPSHOT_FORMAT ||
            snapshot.chain_id !== binding.chainId ||
            snapshot.validator_id !== binding.validatorId ||
            snapshot.epoch !== binding.epoch) {
            throw new VoteLedgerCustodyError("VOTELEDGER_BINDING_MISMATCH", `Snapshot de otra (cadena, validador, época); restauración rechazada`);
        }
        if (!verifyAuth(snapshot, snapshotSignature)) {
            throw new VoteLedgerCustodyError("VOTELEDGER_SNAPSHOT_AUTH_FAILED", `La firma del snapshot no verifica contra el manifiesto; restauración rechazada`);
        }
        if (existsSync(filePath)) {
            throw new VoteLedgerCustodyError("VOTELEDGER_CORRUPT", `Ya existe un registro en ${filePath}; la restauración no sobrescribe registros`);
        }
        const ledger = new DurableVoteLedger(filePath, binding);
        ledger.witnessPath = voteLedgerWitnessPath(binding, options);
        ledger.witnessLockPath = ledger.witnessPath + ".lock";
        mkdirSync(dirname(ledger.witnessPath), { recursive: true });
        ledger.withWitnessLock(() => ledger.withLock(() => {
            // Cabecera + entrada base SNAPSHOT_STATE encadenada al head del snapshot.
            const header = {
                type: "LEDGER_HEADER",
                format: VOTELEDGER_FORMAT,
                chain_id: binding.chainId,
                validator_id: binding.validatorId,
                epoch: binding.epoch,
                seq: 0,
                prev_hash: ZERO_HASH_1024,
            };
            const headerFull = { ...header, checksum: entryChecksum(header) };
            const baseCore = {
                type: "SNAPSHOT_STATE",
                chain_id: binding.chainId,
                validator_id: binding.validatorId,
                epoch: binding.epoch,
                seq: snapshot.upto_entries,
                prev_hash: snapshot.head_hash,
                snapshot,
            };
            const baseFull = { ...baseCore, checksum: entryChecksum(baseCore) };
            const fd = openSync(filePath, "wx");
            let bytes = 0;
            try {
                const l1 = canonicalize(headerFull) + "\n";
                const l2 = canonicalize(baseFull) + "\n";
                writeSync(fd, l1, null, "utf8");
                writeSync(fd, l2, null, "utf8");
                fsyncSync(fd);
                bytes = Buffer.byteLength(l1, "utf8") + Buffer.byteLength(l2, "utf8");
            }
            finally {
                closeSync(fd);
            }
            fsyncDir(dirname(filePath));
            ledger.lastSeq = 0;
            ledger.lastChecksum = headerFull.checksum;
            ledger.headerChecksum = headerFull.checksum;
            ledger.readOffset = bytes;
            // Aplica la base (valida duplicados internamente).
            ledger.applyEntry(baseFull);
            // Log posterior: verificación completa de cada línea contra el ancla.
            // OJO: el encadenado del log posterior original parte del head del
            // snapshot (prev_hash de su primera entrada == snapshot.head_hash).
            // En el fichero restaurado, esa primera entrada debe enlazar con la
            // base: se reescribe su prev_hash al checksum de la base y se
            // recalcula su checksum, manteniendo la cadena interna posterior
            // mediante el mismo procedimiento entrada a entrada.
            let chainPrevDeclared = snapshot.head_hash;
            let writePrev = baseFull.checksum;
            const fd2 = openSync(filePath, "a");
            try {
                for (const raw of tailLines) {
                    const e = ledger.parseLine(raw, -1);
                    if (e.prev_hash !== chainPrevDeclared) {
                        throw new VoteLedgerCustodyError("VOTELEDGER_CORRUPT", `Restauración: el log posterior no continúa el head del snapshot (seq ${e.seq})`);
                    }
                    const { checksum, ...core } = e;
                    if (entryChecksum(core) !== checksum) {
                        throw new VoteLedgerCustodyError("VOTELEDGER_CORRUPT", `Restauración: checksum inválido en el log posterior (seq ${e.seq})`);
                    }
                    if (e.chain_id !== binding.chainId || e.validator_id !== binding.validatorId || e.epoch !== binding.epoch) {
                        throw new VoteLedgerCustodyError("VOTELEDGER_BINDING_MISMATCH", `Restauración: entrada posterior de otra (cadena, validador, época)`);
                    }
                    const rewrittenCore = { ...core, prev_hash: writePrev };
                    const rewritten = { ...rewrittenCore, checksum: entryChecksum(rewrittenCore) };
                    const line = canonicalize(rewritten) + "\n";
                    writeSync(fd2, line, null, "utf8");
                    ledger.applyEntry(rewritten);
                    chainPrevDeclared = e.checksum;
                    writePrev = rewritten.checksum;
                    ledger.readOffset += Buffer.byteLength(line, "utf8");
                }
                fsyncSync(fd2);
            }
            finally {
                closeSync(fd2);
            }
            ledger.writeAnchor();
            fsyncDir(dirname(filePath));
            // Reconciliación con el testigo externo (R7): el estado restaurado
            // debe ser exactamente el último reconocido, o la restauración se
            // rechaza y el fichero recién construido se retira.
            const fp = snapshotFingerprint(snapshot);
            const digest = ledger.stateDigest();
            try {
                if (existsSync(ledger.witnessPath)) {
                    const w = VoteLedgerWitness.load(ledger.witnessPath, binding);
                    const floor = w.floorState;
                    if (!floor || floor.durable_sequence !== ledger.lastSeq || floor.state_digest !== digest) {
                        throw new VoteLedgerCustodyError("VOTELEDGER_RECOVERY_REQUIRED", `Restauración de ${binding.validatorId}: el estado restaurado (secuencia ${ledger.lastSeq}) no es el último reconocido por el testigo externo (secuencia ${floor?.durable_sequence ?? "sin compromiso"}); restauración rechazada y firma DESHABILITADA`);
                    }
                    w.registerRestore({
                        snapshot_hash: fp,
                        durable_sequence: ledger.lastSeq,
                        wal_head_hash: ledger.lastChecksum,
                        state_digest: digest,
                        from_head_hash: floor.wal_head_hash,
                    });
                    ledger.witness = w;
                }
                else {
                    const w = VoteLedgerWitness.create(ledger.witnessPath, binding);
                    w.registerRestore({
                        snapshot_hash: fp,
                        durable_sequence: ledger.lastSeq,
                        wal_head_hash: ledger.lastChecksum,
                        state_digest: digest,
                        from_head_hash: ZERO_HASH_1024,
                    });
                    ledger.witness = w;
                }
            }
            catch (err) {
                // Restauración rechazada tras construir el fichero: se retira lo
                // construido (era nuestro; el destino no existía antes de entrar).
                try {
                    rmSync(filePath, { force: true });
                }
                catch {
                    /* mejor esfuerzo */
                }
                try {
                    rmSync(ledger.anchorPath, { force: true });
                }
                catch {
                    /* mejor esfuerzo */
                }
                throw err;
            }
            ledger.lastProof = ledger.buildProof(true, false, true);
        }));
        return ledger;
    }
}
/**
 * Época del conjunto de validadores: identidad derivada del manifiesto
 * (cadena + claves públicas + quórum). Cambiar cualquier clave cambia la
 * época — y con ella el binding de los registros: una rotación/sustitución
 * de claves NO puede reutilizar el estado de custodia anterior.
 */
export function validatorSetEpoch(manifest) {
    return ("set-" +
        mtDual1024(canonicalBytes({
            chain_id: manifest.chain_id,
            format: "MT-VALIDATOR-MANIFEST-1",
            quorum: manifest.quorum,
            validators: manifest.validators.map((v) => ({ public_key: v.public_key, validator_id: v.validator_id })),
        }), VALIDATOR_SET_EPOCH_DOMAIN).slice(0, 24));
}
/** Ruta convencional del registro duradero de un validador en su directorio. */
export function voteLedgerPath(dir, validatorId) {
    return join(dir, `voteledger-${validatorId}.jsonl`);
}
