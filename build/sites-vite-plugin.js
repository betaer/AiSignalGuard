import { access, cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";

const STATIC_FILES = [
  "404.html",
  "index-20260719.html",
  "index-ipcx.html",
  "index-ipcx-v1.5.0.html",
  "index-ipcx-remix-v1.2.0.html",
  "index-ipcx-remix-v1.3.0.html",
  "app.min.js",
  "starPromptPolicy.js",
  "networkEvidence.js",
  "signalSemantics.js",
  "signalGuardApp.js",
  "ipcx-remix-v1.2.0.js",
  "ipcx-remix-v1.3.0.js",
  "styles.min.css",
  "favicon.svg",
  "assets",
  "demo",
  "tuiguang/social-preview.png",
  "tuiguang/xiaohongshu-cover.png",
  "v1",
  "v2",
];

const LEGACY_SUMMARY_URL =
  /"https:\/\/betaer\.github\.io\/AiSignalGuard\/"/g;
const RUNTIME_SUMMARY_URL =
  'new URL("/", window.location.href).href';

async function exists(path) {
  try {
    await access(path);
    return true;
  } catch (error) {
    if (error?.code === "ENOENT") {
      return false;
    }
    throw error;
  }
}

/** Copy only the browser files intentionally exposed by the static site. */
export function rootStaticAssets() {
  let root = process.cwd();

  return {
    name: "root-static-assets",
    apply: "build",
    applyToEnvironment(environment) {
      return environment.name === "client";
    },
    configResolved(config) {
      root = config.root;
    },
    async writeBundle(outputOptions) {
      if (!outputOptions.dir) {
        throw new Error("root-static-assets requires an output directory");
      }

      await Promise.all(
        STATIC_FILES.map(async (entry) => {
          const destination = resolve(outputOptions.dir, entry);
          await mkdir(dirname(destination), { recursive: true });
          await cp(resolve(root, entry), destination, { recursive: true });
        }),
      );

      const browserBundle = resolve(outputOptions.dir, "app.min.js");
      const source = await readFile(browserBundle, "utf8");
      const rewritten = source.replace(
        LEGACY_SUMMARY_URL,
        RUNTIME_SUMMARY_URL,
      );
      if (rewritten === source) {
        throw new Error(
          "Could not rewrite the deployed summary URL in app.min.js",
        );
      }
      await writeFile(browserBundle, rewritten);
    },
  };
}

/**
 * Package the hosting metadata after Vite finishes compiling.
 */
export function sites() {
  let root = process.cwd();

  return {
    name: "sites",
    apply: "build",
    enforce: "post",
    configResolved(config) {
      root = config.root;
    },
    async closeBundle() {
      const metadataDirectory = resolve(root, "dist", ".openai");
      const hostingConfig = resolve(root, ".openai", "hosting.json");

      await rm(metadataDirectory, { recursive: true, force: true });
      await mkdir(metadataDirectory, { recursive: true });
      if (await exists(hostingConfig)) {
        await cp(hostingConfig, resolve(metadataDirectory, "hosting.json"));
      }
    },
  };
}
