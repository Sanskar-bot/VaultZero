/**
 * src/shims/crypto.js — Browser polyfill for Node's `crypto` module
 *
 * @vaultzero/core imports `import { webcrypto } from "crypto"` (Node API).
 * In the browser, `globalThis.crypto` IS webcrypto.
 *
 * This shim makes the import work in both environments by re-exporting
 * `globalThis.crypto` as `webcrypto`, which is what the core files expect.
 *
 * esbuild aliases `crypto` → this file in browser builds.
 * The Node/backend builds don't use this shim (they use the real Node crypto).
 */

// Export webcrypto as the browser's native crypto object
export const webcrypto = globalThis.crypto;

// Export randomUUID so vault.ts's `webcrypto.randomUUID()` works
export const randomUUID = () => globalThis.crypto.randomUUID();

// Default export for any `import crypto from "crypto"` patterns
export default {
  webcrypto: globalThis.crypto,
  randomUUID: () => globalThis.crypto.randomUUID(),
  getRandomValues: (buf) => globalThis.crypto.getRandomValues(buf),
};
