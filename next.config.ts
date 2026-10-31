import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  /** Bundle minimo autocontenido para la imagen Docker (`.next/standalone`). */
  output: "standalone",
  cacheComponents: true,
  partialPrefetching: true,
  turbopack: {
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
    },
  },
};

export default nextConfig;
