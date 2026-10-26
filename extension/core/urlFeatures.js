import { parseHost } from "./psl.js";

const SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update", "confirm", "banking", "password", "wallet", "suspend",
]

const SHORTENERS = new Set(["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"]);

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

function findKeywords (text){
    return SUSPICIOUS_KEYWORDS.filter((word) => text.includes(word));
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
    const hostEntropy = calcEntropy(host);

    // Entropy of just the registrable name (the "example" in example.co.uk).
    // Falls back to the whole host when there is no registered domain.
    const domainLabel = registeredDomain ? registeredDomain.split(".")[0] : host;
    const domainEntropy = calcEntropy(domainLabel);

    const queryHasUrl = /https?:\/\//i.test(safeDecode(url.search));
    const numEncodedChars = (href.match(/%[0-9a-f]{2}/gi) || []).length;
    const longestLabel = Math.max(...labels.map((l) => l.length));
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
        hostLength: host.length,
        pathLength: url.pathname.length,
        numDots: countChar(host, "."),
        numHyphens: countChar(host, "-"),
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
        hostEntropy,
        domainEntropy,

        queryHasUrl,
        numEncodedChars,
        longestLabel,
        pathExtension,
        isShortener,
    };
}