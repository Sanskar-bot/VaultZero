/**
 * src/popup/index.tsx — React Entry Point
 *
 * Mounts the root App component into #root.
 * Uses React 18 createRoot API.
 */
import { createRoot } from "react-dom/client";
import { App } from "./App";

const rootEl = document.getElementById("root");
if (!rootEl) throw new Error("Root element #root not found");

const root = createRoot(rootEl);
root.render(<App />);
