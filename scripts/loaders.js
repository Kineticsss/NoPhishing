import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parse } from "csv-parse";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const RAW_DIR = path.join(ROOT, "data-raw");
const CACHE_DIR = path.join(RAW_DIR, "cache"); // inside data-raw, so it is gitignored

// Label coding differs per file, so every mapping is explicit.
// Anything unrecognized returns null and is dropped and counted.
export const DATASETS = {
    dataset: {
        file: "Dataset.csv",
        urlCol: "url",
        labelCol: "label",
        mapLabel: (v) => (v === "1" ? "phish" : v === "0" ? "legit" : null),
    },
    phiusiil: {
        file: "PhiUSIIL_Phishing_URL_Dataset.csv",
        urlCol: "URL",
        labelCol: "label",
        // Reversed compared to Dataset.csv: 0 is phishing here.
        mapLabel: (v) => (v === "0" ? "phish" : v === "1" ? "legit" : null),
    },
    siteurls: {
        file: "phishing_site_urls.csv",
        urlCol: "URL",
        labelCol: "Label",
        mapLabel: (v) => (v === "bad" ? "phish" : v === "good" ? "legit" : null),
    },
};

// Rows with no scheme get http:// added and are flagged schemeKnown: false,
// so evaluate.js can skip the HTTPS rules for them.
export function normalizeUrl(raw) {
    const url = String(raw ?? "").trim();
    if (url === "") return null;
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(url)) return { url, schemeKnown: true };
    return { url: "http://" + url, schemeKnown: false };
}

function parseCsv(def, stats) {
    return new Promise((resolve, reject) => {
        const rows = [];
        const input = fs.createReadStream(path.join(RAW_DIR, def.file));
        input.on("error", reject);

        const parser = parse({
            columns: (header) => {
                for (const col of [def.urlCol, def.labelCol]) {
                    if (!header.includes(col)) throw new Error(`Column "${col}" not found in ${def.file}`);
                }
                return header;
            },
            bom: true,
            relax_quotes: true,
            relax_column_count: true,
            skip_records_with_error: true,
            on_skip: () => { stats.skippedMalformed++; },
            // Keep only the two columns we need, so the 55-column files don't fill memory.
            on_record: (rec) => ({ url: rec[def.urlCol], label: rec[def.labelCol] }),
        });

        parser.on("data", (r) => rows.push(r));
        parser.on("end", () => resolve(rows));
        parser.on("error", reject);
        input.pipe(parser);
    });
}

export async function loadDataset(name, { useCache = true } = {}) {
    const def = DATASETS[name];
    if (!def) throw new Error(`Unknown dataset "${name}". Known: ${Object.keys(DATASETS).join(", ")}`);

    const source = path.join(RAW_DIR, def.file);
    if (!fs.existsSync(source)) throw new Error(`Missing file: ${source}`);

    const cacheFile = path.join(CACHE_DIR, `${name}.jsonl`);
    const statsFile = path.join(CACHE_DIR, `${name}.stats.json`);

    if (useCache && fs.existsSync(cacheFile) && fs.existsSync(statsFile)
        && fs.statSync(cacheFile).mtimeMs > fs.statSync(source).mtimeMs) {
        const rows = fs.readFileSync(cacheFile, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
        const stats = { ...JSON.parse(fs.readFileSync(statsFile, "utf8")), fromCache: true };
        return { name, rows, stats };
    }

    const stats = { rawRows: 0, skippedMalformed: 0, emptyUrl: 0, badLabel: 0, duplicates: 0, conflicts: 0 };
    const raw = await parseCsv(def, stats);
    stats.rawRows = raw.length;

    const seen = new Map();        // url -> row
    const conflicted = new Set();  // urls that appear with both labels

    for (const r of raw) {
        const label = def.mapLabel(String(r.label ?? "").trim().toLowerCase());
        if (!label) { stats.badLabel++; continue; }
        const n = normalizeUrl(r.url);
        if (!n) { stats.emptyUrl++; continue; }

        const prev = seen.get(n.url);
        if (!prev) seen.set(n.url, { url: n.url, label, schemeKnown: n.schemeKnown });
        else if (prev.label !== label) conflicted.add(n.url);
        else stats.duplicates++;
    }

    const rows = [...seen.values()].filter((r) => !conflicted.has(r.url));
    stats.conflicts = conflicted.size;
    stats.kept = rows.length;
    stats.phish = rows.filter((r) => r.label === "phish").length;
    stats.legit = stats.kept - stats.phish;
    stats.withScheme = rows.filter((r) => r.schemeKnown).length;
    stats.fromCache = false;

    fs.mkdirSync(CACHE_DIR, { recursive: true });
    fs.writeFileSync(cacheFile, rows.map((r) => JSON.stringify(r)).join("\n"));
    fs.writeFileSync(statsFile, JSON.stringify(stats, null, 2));
    return { name, rows, stats };
}

// Running `node scripts/loaders.js [names] [--refresh]` prints stats as a self-check.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
    const names = process.argv.slice(2).filter((a) => !a.startsWith("--"));
    const targets = names.length ? names : Object.keys(DATASETS);
    const useCache = !process.argv.includes("--refresh");
    for (const name of targets) {
        console.time(name);
        const { stats } = await loadDataset(name, { useCache });
        console.timeEnd(name);
        console.log(name, stats);
    }
}