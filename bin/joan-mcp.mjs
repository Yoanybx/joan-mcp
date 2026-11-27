#!/usr/bin/env node
/**
 * joan-mcp launcher (npm bin).
 *
 * The judge loads its JOAN-side adapter from JOAN_INTEGRATION_DIR.
 * Inside this package the adapter ships under ./joan-integracion-m7,
 * so when the caller does not set the variable we default it to the
 * bundled tree. An explicitly set JOAN_INTEGRATION_DIR always wins,
 * exactly as with the standalone server file.
 */
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
if (!process.env.JOAN_INTEGRATION_DIR) {
  process.env.JOAN_INTEGRATION_DIR = join(here, "..", "joan-integracion-m7");
}
await import(pathToFileURL(join(here, "..", "joan-mcp.mjs")).href);
