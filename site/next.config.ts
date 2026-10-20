import type { NextConfig } from "next";
import createMDX from "@next/mdx";
import path from "node:path";

const isDev = process.env.NODE_ENV === "development";
// CI builds use their repository's Pages path; standalone production builds
// default to the LFDT destination. DOCS_BASE_PATH still supports custom hosts.
const repositoryName =
  process.env.GITHUB_REPOSITORY?.split("/").pop() || "permissioned-privacy-control";

const basePath =
  process.env.DOCS_BASE_PATH !== undefined
    ? process.env.DOCS_BASE_PATH
    : isDev
      ? ""
      : `/${repositoryName}`;

const nextConfig: NextConfig = {
  pageExtensions: ["ts", "tsx", "md", "mdx"],
  ...(isDev ? {} : { output: "export" }),
  basePath,
  env: {
    // Expose the base path to client/server components so non-route assets
    // in public/ (e.g. /openapi.json) can be referenced with the correct
    // GitHub Pages prefix. next/link handles this automatically for routes;
    // plain fetches and <a href> do not.
    NEXT_PUBLIC_BASE_PATH: basePath,
  },
  trailingSlash: true,
  images: {
    unoptimized: true,
  },
  turbopack: {
    root: __dirname,
  },
};

const withMDX = createMDX({
  options: {
    remarkPlugins: ["remark-gfm", path.join(__dirname, "remark-mermaid.mjs")],
    rehypePlugins: ["rehype-slug"],
  },
});

export default withMDX(nextConfig);
