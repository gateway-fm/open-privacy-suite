// The deployed site lives under a base path on GitHub Pages
// (the CI repository name, or /permissioned-privacy-control for a local
// production build; overridable via DOCS_BASE_PATH at build time).
// next/link prefixes route hrefs automatically, but static assets in
// public/ referenced via fetch() or plain <a href> need the prefix
// applied manually. NEXT_PUBLIC_BASE_PATH is injected in next.config.ts
// from the same value passed to Next's basePath option.
export const basePath = process.env.NEXT_PUBLIC_BASE_PATH ?? "";

export function withBasePath(path: string): string {
  return `${basePath}${path}`;
}
