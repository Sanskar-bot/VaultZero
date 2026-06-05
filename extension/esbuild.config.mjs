/**
 * esbuild configuration for VaultZero browser extension
 *
 * Builds three separate bundles:
 * 1. background.js  — service worker (no DOM access)
 * 2. content.js     — content script (isolated world, DOM access)
 * 3. popup.js       — React popup UI
 *
 * Uses ESM format for Manifest V3 service worker compatibility.
 */

import * as esbuild from "esbuild";

const isWatch = process.argv.includes("--watch");

/** @type {esbuild.BuildOptions} */
const commonOptions = {
  bundle: true,
  sourcemap: true,
  target: "chrome110",
  minify: !isWatch,
  logLevel: "info",
};

const builds = [
  // Background service worker
  esbuild.context({
    ...commonOptions,
    entryPoints: ["src/background/service-worker.ts"],
    outfile: "dist/background.js",
    format: "esm",
  }),

  // Content script
  esbuild.context({
    ...commonOptions,
    entryPoints: ["src/content/content-script.ts"],
    outfile: "dist/content.js",
    format: "iife", // content scripts must be IIFE
  }),

  // Popup React app
  esbuild.context({
    ...commonOptions,
    entryPoints: ["src/popup/index.tsx"],
    outfile: "dist/popup.js",
    format: "iife",
    jsx: "automatic",
  }),
];

async function main() {
  const contexts = await Promise.all(builds);

  if (isWatch) {
    await Promise.all(contexts.map((ctx) => ctx.watch()));
    console.log("[esbuild] Watching for changes...");
  } else {
    await Promise.all(contexts.map((ctx) => ctx.rebuild()));
    await Promise.all(contexts.map((ctx) => ctx.dispose()));
    console.log("[esbuild] Build complete.");
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
