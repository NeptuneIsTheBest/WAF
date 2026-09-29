import { defineConfig } from "vite";
import { readFileSync } from "node:fs";
export default defineConfig({
  base: "/.waf/challenge/assets/",
  plugins: [
    {
      name: "altcha-license",
      generateBundle() {
        this.emitFile({
          type: "asset",
          fileName: "LICENSE.txt",
          source: readFileSync("node_modules/altcha/LICENSE.txt", "utf8"),
        });
      },
    },
  ],
  build: {
    outDir: "dist/challenge",
    emptyOutDir: true,
    rollupOptions: {
      input: "src/challenge.ts",
      output: {
        entryFileNames: "challenge.js",
        assetFileNames: (asset) =>
          asset.names?.some((name) => name.endsWith(".css"))
            ? "challenge.css"
            : "[name]-[hash][extname]",
      },
    },
  },
});
