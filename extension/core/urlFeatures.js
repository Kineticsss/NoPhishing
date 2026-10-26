import { parseHost } from "./psl.js";
import { BRANDS } from "./data/brands.js";

const STRONG_KEYWORDS = ["login", "signin", "verify", "password", "wallet", "suspend"];
const WEAK_KEYWORDS = ["account", "secure", "update", "confirm", "banking"];
const SUSPICIOUS_KEYWORDS = [...STRONG_KEYWORDS, ...WEAK_KEYWORDS];

const SHORTENERS = new Set(["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"]);
const COMMON_TLDS = new Set(["com", "net", "org", "edu", "gov"]);

function countChar (str, ch){
    return str.split(ch).length-1;
}

function countDigits (str){
    return (str.match(/\d/g) || []).length;
}

function isIpAddress(host){
    const isIPv4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
    const isIPv6 = host.startsWith("[");
    return isIPv4 || isIPv6;
}

// A keyword must be a whole token, or sit at the start or end of one.
function findKeywords (text){
    const tokens = text.split(/[^a-z0-9]+/).filter(Boolean);
    return SUSPICIOUS_KEYWORDS.filter((kw) =>
        tokens.some((t) => t === kw || t.startsWith(kw) || t.endsWith(kw)));
}

function safeDecode (s){
    try { return decodeURIComponent(s); } catch { return s; }
}

function calcEntropy (str){
    if (str.length === 0) return 0;

    const counts = {};
    for (const c of str){
        counts[c] = (counts[c] || 0) + 1;
    }

    let entropy = 0;
    for (const count of Object.values(counts)){
        const p = count / str.length;
        entropy -= p * Math.log2(p);
    }
    return entropy;
}

function brandMatch (token, brand){
    return token === brand.name || (!brand.exact && token.startsWith(brand.name));
}

// Names of brands found in the tokens, skipping brands the site really owns.
function findBrands (tokens, ownsBrand){
    return BRANDS.filter((b) => !ownsBrand(b) && tokens.some((t) => brandMatch(t, b))).map((b) => b.name);
}

// Letters and digits mixed in a way real names rarely are ("hidok4f8zl", "syk1pe9wox").
function looksRandom (label){
    if (label.length < 6) return false;
    let switches = 0;
    for (let i = 1; i < label.length; i++){
        const a = label[i - 1], b = label[i];
        if ((/[a-z]/.test(a) && /\d/.test(b)) || (/\d/.test(a) && /[a-z]/.test(b))) switches++;
    }
    return switches >= 2;
}

export function extractFeatures (rawUrl) {
    let url;

    try{
        url = new URL(String(rawUrl).trim());
    } catch {
        return { analyzable: false, reason: "invalid_url" };
    }

    if (url.protocol !== "http:" && url.protocol !== "https:"){
        return { analyzable: false, reason: "unsupported_protocol" };
    }

    const href = url.href;
    const host = url.hostname.toLowerCase().replace(/\.$/, "");
    const numDigits = countDigits(href);
    const labels = host.split(".");

    // Punycode labels ("xn--80afa...") would inflate the hyphen, length and entropy rules.
    const plainLabels = labels.map((l) => (l.startsWith("xn--") ? l.slice(4) : l));
    const plainHost = plainLabels.join(".");

    const isIpHost = isIpAddress(host);

    // Domain structure comes from the Public Suffix List. IP hosts have none.
    const psl = isIpHost ? null : parseHost(host);
    const tld = psl ? psl.tld : null;
    const publicSuffix = psl ? psl.publicSuffix : null;
    const registeredDomain = psl ? psl.registeredDomain : null;
    const subdomain = psl ? psl.subdomain : "";
    const subdomainCount = psl ? psl.subdomainCount : 0;
    const isSharedHosting = psl ? psl.isSharedHosting : false;

    const isPunycode = labels.some((label) => label.startsWith("xn--"));
    const hasUserInfo = url.username !== "" || url.password !== "";
    const userInfoLooksLikeDomain = url.username.includes(".");
    const hasPortNumber = url.port !== "";
    const pathDepth = url.pathname.split("/").filter(Boolean).length;
    const numQueryParams = [...url.searchParams].length;

    const hostKeywords = findKeywords(host);
    const pathKeywords = findKeywords(safeDecode(url.pathname).toLowerCase());
    const queryKeywords = findKeywords(safeDecode(url.search).toLowerCase());
    const isStrong = (kw) => STRONG_KEYWORDS.includes(kw);
    const hostStrongKeywords = hostKeywords.filter(isStrong);
    const hasStrongKeyword = [...hostKeywords, ...pathKeywords, ...queryKeywords].some(isStrong);

    const hostEntropy = calcEntropy(plainHost);

    // The registrable name (the "example" in example.co.uk).
    const domainLabel = registeredDomain ? registeredDomain.split(".")[0] : host;
    const domainEntropy = domainLabel.startsWith("xn--") ? 0 : calcEntropy(domainLabel);

    const subdomainHasTld = subdomain.split(".").slice(1).some((l) => COMMON_TLDS.has(l));
    const hostDigitRatio = isPunycode || host.length === 0 ? 0 : countDigits(host) / host.length;

    // Brand impersonation. On shared hosting the registered name is chosen by whoever signed up,
    // so it counts as part of the subdomain, and nobody "owns" a brand there.
    const ownsBrand = (b) => !isSharedHosting && (domainLabel === b.name || (b.domains ?? []).includes(registeredDomain));
    const subTokens = (isSharedHosting ? `${subdomain}.${domainLabel}` : subdomain).split(/[.\-_]/).filter(Boolean);
    const pathCandidates = safeDecode(url.pathname).toLowerCase().split("/").filter(Boolean)
        .map((s) => s.replace(/\.(html?|php|aspx?|jsp)$/, ""))
        .flatMap((s) => [s, ...s.split(".")]);
    const brandsInSubdomain = findBrands(subTokens, ownsBrand);
    const brandsInPath = findBrands(pathCandidates, ownsBrand);
    const sharedHostRandomLabel = isSharedHosting && looksRandom(domainLabel);

    const queryHasUrl = /https?:\/\//i.test(safeDecode(url.search));
    const numEncodedChars = (href.match(/%[0-9a-f]{2}/gi) || []).length;
    const longestLabel = Math.max(...plainLabels.map((l) => l.length));
    const lastSegment = url.pathname.split("/").filter(Boolean).pop() || "";
    const dotIndex = lastSegment.lastIndexOf(".");
    const pathExtension = dotIndex > 0 ? lastSegment.slice(dotIndex + 1).toLowerCase() : "";
    const isShortener = SHORTENERS.has(host);

    return{
        analyzable: true,
        href,
        protocol: url.protocol,
        host,
        path: url.pathname,
        query: url.search,
        username: url.username,
        port: url.port,

        urlLength: href.length,
        hostLength: plainHost.length,
        pathLength: url.pathname.length,
        numDots: countChar(host, "."),
        numHyphens: countChar(plainHost, "-"),
        numDigits,
        digitRatio: href.length === 0 ? 0 : numDigits / href.length,
        hasHttps: url.protocol === "https:",
        isIpHost,
        tld,
        publicSuffix,
        registeredDomain,
        subdomain,
        subdomainCount,
        isSharedHosting,
        isPunycode,
        hasUserInfo,
        userInfoLooksLikeDomain,
        hasPortNumber,
        pathDepth,
        numQueryParams,
        hostKeywords,
        pathKeywords,
        queryKeywords,
        hostStrongKeywords,
        hasStrongKeyword,
        hostEntropy,
        domainEntropy,
        subdomainHasTld,
        hostDigitRatio,

        brandsInSubdomain,
        brandsInPath,
        sharedHostRandomLabel,

        queryHasUrl,
        numEncodedChars,
        longestLabel,
        pathExtension,
        isShortener,
    };
}