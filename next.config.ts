import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  turbopack: {
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
    },
  },
  experimental: {
    serverActions: {
      // Allow large installers (e.g. 200MB .exe)
      bodySizeLimit: "512mb",
    },
    proxyClientMaxBodySize: "512mb",
  },
};

export default nextConfig;
