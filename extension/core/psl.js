import rawList from "./data/publicSuffixList.js";

const rules = new Map();      // "co.uk" -> isPrivate
const wildcards = new Map();  // "*.ck" is stored as "ck" -> isPrivate
const exceptions = new Set(); // "!www.ck" is stored as "www.ck"

// The URL parser gives us punycode hosts, so Unicode rules must be converted to match.
function toAscii(s) {
    if (!/[^\x00-\x7f]/.test(s)) return s;
    try { return new URL("http://" + s).hostname; } catch { return s; }
}

let inPrivate = false;
for (const rawLine of rawList.split("\n")) {
    const line = rawLine.trim();
    if (line.startsWith("//")) {
        if (line.includes("===BEGIN PRIVATE DOMAINS===")) inPrivate = true;
        continue;
    }
    if (line === "") continue;

    const rule = line.split(/\s+/)[0].toLowerCase();
    if (rule.startsWith("!")) {
        exceptions.add(toAscii(rule.slice(1)));
    } else if (rule.startsWith("*.")) {
        wildcards.set(toAscii(rule.slice(2)), inPrivate);
    } else {
        rules.set(toAscii(rule), inPrivate);
    }
}

// Do not call this on IP addresses; check isIpHost first.
export function parseHost(host) {
    const labels = host.toLowerCase().replace(/\.$/, "").split(".");
    let suffixLen = 1;      // default rule: the last label is the suffix
    let isPrivate = false;

    for (let i = 0; i < labels.length; i++) {
        const candidate = labels.slice(i).join(".");
        const parent = labels.slice(i + 1).join(".");

        if (exceptions.has(candidate)) {
            suffixLen = labels.length - i - 1;
            break;
        }
        if (rules.has(candidate)) {
            suffixLen = labels.length - i;
            isPrivate = rules.get(candidate);
            break;
        }
        if (parent !== "" && wildcards.has(parent)) {
            suffixLen = labels.length - i;
            isPrivate = wildcards.get(parent);
            break;
        }
    }

    const publicSuffix = labels.slice(labels.length - suffixLen).join(".");
    const tld = labels[labels.length - 1];

    if (labels.length <= suffixLen) {
        // The host is itself a public suffix, so there is no registrable domain.
        return { publicSuffix, tld, registeredDomain: null, subdomain: "", subdomainCount: 0, isSharedHosting: isPrivate };
    }

    const subLabels = labels.slice(0, labels.length - suffixLen - 1);
    return {
        publicSuffix,
        tld,
        registeredDomain: labels.slice(labels.length - suffixLen - 1).join("."),
        subdomain: subLabels.join("."),
        subdomainCount: subLabels.length,
        isSharedHosting: isPrivate,
    };
}