/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Override the API origin. Empty by default: Vite proxies /api in dev. */
  readonly VITE_API_BASE?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
