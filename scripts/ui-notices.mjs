// Print the full license and attribution files of installed Tower production packages.
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";

const root = path.resolve(process.argv[2] ?? "tower");
const lock = JSON.parse(readFileSync(path.join(root, "package-lock.json"), "utf8"));
for (const [relative, info] of Object.entries(lock.packages).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)) {
  if (!relative.startsWith("node_modules/") || info.dev) continue;
  const directory = path.join(root, relative);
  const metadata = JSON.parse(readFileSync(path.join(directory, "package.json"), "utf8"));
  const files = readdirSync(directory).filter((name) => /^(licen[cs]e|copying|copyright|notice|unlicense)([.-]|$)/i.test(name)).sort();
  if (!files.length) throw new Error(`No license/notice file found for ${metadata.name} ${metadata.version}`);
  console.log(`\n======================================================================\nTower: ${metadata.name} ${metadata.version}`);
  for (const file of files) console.log(`\n${file}\n${readFileSync(path.join(directory, file), "utf8")}`);
}
