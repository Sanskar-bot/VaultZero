/**
 * esbuild.config.js — VaultZero Extension Build Script
 *
 * Three independent bundles:
 *   1. dist/background.js  — ESM format (Chrome MV3 service worker)
 *   2. dist/content.js     — IIFE format (injected into web pages)
 *   3. dist/popup.js       — IIFE format (loaded by popup.html)
 *
 * Why separate bundles?
 *   - Background: needs ESM for top-level await and module syntax (MV3 requires it)
 *   - Content: IIFE wraps code in a function scope to avoid polluting global scope
 *     of web pages. Also avoids module semantics which require <script type="module">
 *   - Popup: IIFE is safest for CSP compliance ("script-src 'self'" with no 'unsafe-eval')
 *
 * Usage:
 *   Development (with source maps, no minification):
 *     node esbuild.config.js
 *
 *   Watch mode (rebuild on file change):
 *     WATCH=true node esbuild.config.js
 *
 *   Production (minified, no source maps):
 *     NODE_ENV=production node esbuild.config.js
 */

import * as esbuild from "esbuild";
import path from "path";
import { fileURLToPath } from "url";
import { createRequire } from "module";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const require   = createRequire(import.meta.url);

const isDev  = process.env.NODE_ENV !== "production";
const isWatch = process.env.WATCH === "true";

// API_URL injected at build time so it can differ between local/prod builds.
// Falls back to localhost:3000 if not set in environment.
const API_URL = process.env.API_URL ?? "http://localhost:3000";

/**
 * @vaultzero/core uses `import { webcrypto } from "crypto"` (Node API).
 * In the browser, webcrypto is globalThis.crypto. We inject a shim module
 * that re-exports webcrypto as the browser's globalThis.crypto.
 *
 * We also alias libsodium's ESM entry that imports a local .mjs file Chrome
 * can't resolve. We redirect to the CJS build of libsodium-wrappers-sumo,
 * which esbuild can handle.
 */
const libsodiumCjs = require.resolve("libsodium-wrappers-sumo");

/** Shared options applied to all three bundles */
const sharedConfig = {
  bundle:    true,
  minify:    !isDev,              // minify in production, readable in dev
  sourcemap: isDev ? "linked" : false,  // .js.map files only in dev
  target:    ["chrome120", "firefox121"],
  define: {
    "process.env.API_URL":  JSON.stringify(API_URL),
    "process.env.NODE_ENV": JSON.stringify(process.env.NODE_ENV ?? "development"),
    "process.env":          "{}",
    // Polyfill Node's `webcrypto` to the browser's `globalThis.crypto`
    "webcrypto":            "globalThis.crypto",
  },
  alias: {
    // Redirect `import { webcrypto } from "crypto"` → the browser's crypto object
    "crypto": path.join(__dirname, "src/shims/crypto.js"),
    // Redirect libsodium's ESM (which imports a local .mjs) → CJS build
    "libsodium-wrappers-sumo": libsodiumCjs,
  },
};

const bundles = [
  {
    ...sharedConfig,
    entryPoints: [path.join(__dirname, "src/background/index.ts")],
    outfile:     path.join(__dirname, "dist/background.js"),
    format:      "esm",   // MV3 service workers require ESM
    platform:    "browser",
    conditions:  ["browser"],
  },
  {
    ...sharedConfig,
    entryPoints: [path.join(__dirname, "src/content/index.ts")],
    outfile:     path.join(__dirname, "dist/content.js"),
    format:      "iife",  // IIFE: self-contained, no global scope leakage
    platform:    "browser",
    conditions:  ["browser"],
    // Content scripts run in ISOLATED world — no chrome.* APIs available by default
    // except those explicitly allowed by manifest permissions
    globalName:  "VaultZeroContent",
  },
  {
    ...sharedConfig,
    entryPoints: [path.join(__dirname, "src/popup/index.tsx")],
    outfile:     path.join(__dirname, "dist/popup.js"),
    format:      "iife",  // Required for CSP "script-src 'self'" (no eval, no import())
    platform:    "browser",
    conditions:  ["browser"],
    globalName:  "VaultZeroPopup",
  },
];

if (isWatch) {
  // Watch mode: rebuild on every file change
  const contexts = await Promise.all(bundles.map((b) => esbuild.context(b)));
  await Promise.all(contexts.map((ctx) => ctx.watch()));
  console.log("👁  Watching for changes... (Ctrl+C to stop)");
} else {
  // One-shot build
  const results = await Promise.all(bundles.map((b) => esbuild.build(b)));

  let hadErrors = false;
  results.forEach((result, i) => {
    const name = ["background", "content", "popup"][i];
    if (result.errors.length > 0) {
      console.error(`❌ ${name}: ${result.errors.length} error(s)`);
      hadErrors = true;
    } else {
      const minTag = !isDev ? " (minified)" : "";
      console.log(`✓  dist/${name}.js built${minTag}`);
    }
  });

  if (hadErrors) process.exit(1);
  console.log(`\nBuild complete — ${isDev ? "development" : "production"} mode`);
}
