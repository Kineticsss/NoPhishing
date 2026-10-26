// Usage: node scripts/evaluate.js [dataset ...] [--refresh] [--tld] [--export]
//   --refresh  rebuild the dataset caches from the CSVs
//   --tld      also print which TLDs are over-represented among phishing URLs
//   --export   write per-URL results to data-raw/out/<dataset>.csv (for a notebook later)
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { loadDataset, DATASETS } from "./loaders.js";
import { extractFeatures } from "../extension/core/urlFeatures.js";
import { scoreFeatures, THRESHOLDS } from "../extension/core/scorer.js";
import { RULES } from "../extension/core/rules.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const OUT_DIR = path.join(ROOT, "data-raw", "out"); // inside data-raw, so it is gitignored

// The only rules that read hasHttps. Rows with no scheme in the source can't be judged on these.
const HTTPS_RULES = ["R_NO_HTTPS", "R_KEYWORD_NO_HTTPS"];
const SAMPLE_SIZE = 12;
const MIN_TLD_SUPPORT = 200;
const GATE_CUTOFF = THRESHOLDS.LOG; // extra column in the summary: a possible "show the gate" level

const args = process.argv.slice(2);
const refresh = args.includes("--refresh");
const showTlds = args.includes("--tld");
const doExport = args.includes("--export");
const names = args.filter((a) => !a.startsWith("--"));
const targets = names.length ? names : Object.keys(DATASETS);

const pct = (n, d, empty = "-") => (d === 0 ? empty : ((100 * n) / d).toFixed(2) + "%");

const FPR_BUDGET = 0.0005; // 0.05%
function recallAtFpr(phish, legit, budget) {
    for (let t = 0; t <= 100; t++) {
        if (atOrAbove(legit.byScore, t) / legit.analyzed <= budget) {
            return { cutoff: t, recall: atOrAbove(phish.byScore, t) / phish.analyzed };
        }
    }
    return { cutoff: 101, recall: 0 };
}

const atOrAbove = (counts, t) => counts.slice(t).reduce((a, b) => a + b, 0);
const csv = (s) => `"${String(s).replaceAll('"', '""')}"`;
const bump = (map, key, by = 1) => map.set(key, (map.get(key) ?? 0) + by);

const newClass = () => ({
    total: 0,
    unanalyzable: 0,
    analyzed: 0,
    schemeKnownAnalyzed: 0,
    byScore: new Array(101).fill(0),
    fires: new Map(),
});

// Plain ASCII table, so saved output is readable whatever the terminal encoding is.
function printTable(rows) {
    if (rows.length === 0) { console.log("(none)\n"); return; }
    const cols = Object.keys(rows[0]);
    const widths = cols.map((c) => Math.max(c.length, ...rows.map((r) => String(r[c]).length)));
    const line = (cells) => "| " + cells.map((c, i) => String(c).padEnd(widths[i])).join(" | ") + " |";
    console.log(line(cols));
    console.log("|-" + widths.map((w) => "-".repeat(w)).join("-|-") + "-|");
    for (const r of rows) console.log(line(cols.map((c) => r[c])));
    console.log();
}

function printTlds(tlds, baseShare) {
    const rows = [...tlds.entries()]
        .map(([tld, v]) => ({ tld, phish: v.phish, legit: v.legit, total: v.phish + v.legit, share: v.phish / (v.phish + v.legit) }))
        .filter((r) => r.total >= MIN_TLD_SUPPORT)
        .sort((a, b) => b.share - a.share)
        .slice(0, 20)
        .map((r) => ({
            tld: r.tld,
            phish: r.phish,
            legit: r.legit,
            "phish share": (r.share * 100).toFixed(1) + "%",
            "vs baseline": baseShare ? (r.share / baseShare).toFixed(1) + "x" : "-",
        }));
    console.log(`TLDs by phishing share (at least ${MIN_TLD_SUPPORT} URLs; dataset baseline ${(baseShare * 100).toFixed(1)}%):`);
    printTable(rows);
}

async function evaluate(name) {
    const { rows } = await loadDataset(name, { useCache: !refresh });
    const cls = { phish: newClass(), legit: newClass() };
    const falsePositives = [];   // legit URLs that reached "blocked"
    const falseWarns = [];       // legit URLs that reached the warn level
    const misses = [];           // phishing URLs that scored 0
    const errorsByRule = new Map(); // rule id -> { count, message }
    const unanalyzable = new Map(); // reason -> count
    const unanalyzableSamples = [];
    const tlds = new Map();
    let ruleErrors = 0;
    let extractErrors = 0;

    let outFd = null;
    let buffer = [];
    if (doExport) {
        fs.mkdirSync(OUT_DIR, { recursive: true });
        outFd = fs.openSync(path.join(OUT_DIR, `${name}.csv`), "w");
        fs.writeSync(outFd, ["url", "label", "schemeKnown", "registeredDomain", "score", "verdict", ...RULES.map((r) => r.id)].join(",") + "\n");
    }

    console.time(`scoring ${name}`);
    for (const row of rows) {
        const c = cls[row.label];
        c.total++;

        let f;
        try {
            f = extractFeatures(row.url);
        } catch (err) {
            extractErrors++;
            c.unanalyzable++;
            continue;
        }
        if (!f.analyzable) {
            c.unanalyzable++;
            bump(unanalyzable, f.reason ?? "unknown");
            if (unanalyzableSamples.length < 5) unanalyzableSamples.push({ reason: f.reason, url: row.url.slice(0, 90) });
            continue;
        }

        const res = scoreFeatures(f, { skipRules: row.schemeKnown ? [] : HTTPS_RULES });
        c.analyzed++;
        if (row.schemeKnown) c.schemeKnownAnalyzed++;
        c.byScore[res.score]++;

        for (const e of res.errors) {
            ruleErrors++;
            const prev = errorsByRule.get(e.id);
            if (prev) prev.count++;
            else errorsByRule.set(e.id, { count: 1, message: e.message.slice(0, 80) });
        }
        for (const r of res.rules_fired) bump(c.fires, r.id);

        if (showTlds && f.tld) {
            const key = args.includes("--suffix") ? f.publicSuffix : f.tld;
            const t = tlds.get(key) ?? { phish: 0, legit: 0 };
            t[row.label]++;
            tlds.set(key, t);
        }

        const info = { score: res.score, url: row.url.slice(0, 90), rules: res.rules_fired.map((r) => r.id).join(" ") };
        if (row.label === "legit" && res.verdict === "blocked" && falsePositives.length < SAMPLE_SIZE) falsePositives.push(info);
        if (row.label === "legit" && res.score >= THRESHOLDS.LOG && falseWarns.length < SAMPLE_SIZE) falseWarns.push(info);
        if (row.label === "phish" && res.score === 0 && misses.length < SAMPLE_SIZE) misses.push(info);

        if (outFd !== null) {
            const fired = new Set(res.rules_fired.map((r) => r.id));
            buffer.push([
                csv(row.url), row.label, row.schemeKnown ? 1 : 0, csv(f.registeredDomain ?? ""),
                res.score, res.verdict, ...RULES.map((r) => (fired.has(r.id) ? 1 : 0)),
            ].join(","));
            if (buffer.length >= 5000) { fs.writeSync(outFd, buffer.join("\n") + "\n"); buffer = []; }
        }
    }
    if (outFd !== null) {
        if (buffer.length) fs.writeSync(outFd, buffer.join("\n") + "\n");
        fs.closeSync(outFd);
    }
    console.timeEnd(`scoring ${name}`);

    const { phish, legit } = cls;
    const errors = ruleErrors + extractErrors;
    console.log(`\n=== ${name}: phish ${phish.analyzed} / legit ${legit.analyzed} analyzed` +
        ` (unanalyzable: ${phish.unanalyzable + legit.unanalyzable}, rule errors: ${ruleErrors}, extractor errors: ${extractErrors}) ===`);

    if (errors > 0) {
        console.log(`\n!!! ${errors} ERRORS - THESE RESULTS ARE INVALID. Fix the cause below first. !!!`);
        printTable([...errorsByRule.entries()].map(([id, e]) => ({ rule: id, count: e.count, "first message": e.message })));
    }

    if (unanalyzable.size) {
        console.log("Unanalyzable URLs by reason:");
        printTable([...unanalyzable.entries()].map(([reason, count]) => ({ reason, count })));
        printTable(unanalyzableSamples);
    }

    // Threshold sweep: at each cutoff, what share of each class scores at or above it.
    const cutoffs = [...new Set([10, 20, THRESHOLDS.LOG, THRESHOLDS.WARN, 50, THRESHOLDS.BLOCK, 70, 80])].sort((a, b) => a - b);
    console.log("Threshold sweep (WARN and BLOCK marked):");
    printTable(cutoffs.map((t) => {
        const tp = atOrAbove(phish.byScore, t);
        const fp = atOrAbove(legit.byScore, t);
        return {
            cutoff: t + (t === THRESHOLDS.WARN ? " WARN" : t === THRESHOLDS.BLOCK ? " BLOCK" : ""),
            "recall (phish caught)": pct(tp, phish.analyzed),
            "false positive rate": pct(fp, legit.analyzed),
            precision: pct(tp, tp + fp),
            "legit flagged": fp,
        };
        console.log("('-' means no URL reached that score.)\n");
    }));

    // Per-rule fire rates. HTTPS rules use only the rows that had a real scheme.
    console.log("Per-rule fire rates (lift = phish rate / legit rate):");
    printTable(RULES.map((rule) => {
        const isHttps = HTTPS_RULES.includes(rule.id);
        const dPhish = isHttps ? phish.schemeKnownAnalyzed : phish.analyzed;
        const dLegit = isHttps ? legit.schemeKnownAnalyzed : legit.analyzed;
        const pr = dPhish ? (phish.fires.get(rule.id) ?? 0) / dPhish : 0;
        const lr = dLegit ? (legit.fires.get(rule.id) ?? 0) / dLegit : 0;
        return {
            sortKey: pr,
            rule: rule.id,
            group: rule.group ?? "-",
            weight: rule.weight,
            "phish %": (pr * 100).toFixed(2),
            "legit %": (lr * 100).toFixed(2),
            lift: lr === 0 ? (pr === 0 ? "-" : "inf") : (pr / lr).toFixed(1),
        };
    }).sort((a, b) => b.sortKey - a.sortKey).map(({ sortKey, ...rest }) => rest));

    if (showTlds) {
        const base = phish.analyzed + legit.analyzed ? phish.analyzed / (phish.analyzed + legit.analyzed) : 0;
        printTlds(tlds, base);
    }

    console.log(`Legit URLs that were BLOCKED (score >= ${THRESHOLDS.BLOCK}, first few):`);
    printTable(falsePositives);
    console.log(`Legit URLs at LOG level or above (score >= ${THRESHOLDS.LOG}, first few):`);
    printTable(falseWarns);
    console.log("Phishing URLs that scored 0 (misses, first few):");
    printTable(misses);

    const rateRow = (t) => [
        pct(atOrAbove(phish.byScore, t), phish.analyzed),
        pct(atOrAbove(legit.byScore, t), legit.analyzed),
    ];
    const [rL, fL] = rateRow(THRESHOLDS.LOG);
    const [rW, fW] = rateRow(THRESHOLDS.WARN);
    const [rB, fB] = rateRow(THRESHOLDS.BLOCK);
    const yard = recallAtFpr(phish, legit, FPR_BUDGET);
    return {
        dataset: name,
        phish: phish.analyzed,
        legit: legit.analyzed,
        "recall @0.05% FPR": pct(yard.recall * phish.analyzed, phish.analyzed),
        "(at cutoff)": yard.cutoff,
        [`recall@${THRESHOLDS.LOG}`]: rL, [`FPR@${THRESHOLDS.LOG}`]: fL,
        [`recall@${THRESHOLDS.WARN}`]: rW, [`FPR@${THRESHOLDS.WARN}`]: fW,
        [`recall@${THRESHOLDS.BLOCK}`]: rB, [`FPR@${THRESHOLDS.BLOCK}`]: fB,
        errors,
    };
}

console.time("total");
const summaries = [];
for (const name of targets) summaries.push(await evaluate(name));
console.timeEnd("total");

console.log("\n=== SUMMARY ===");
printTable(summaries);

const totalErrors = summaries.reduce((sum, s) => sum + s.errors, 0);
if (totalErrors > 0) {
    console.log(`!!! ${totalErrors} ERRORS IN TOTAL - DO NOT TRUST THESE NUMBERS !!!`);
    process.exitCode = 1;
}