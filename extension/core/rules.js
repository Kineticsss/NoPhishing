// Weights are starting guesses. Tune them with scripts/evaluate.js on a labeled dataset.
// Tiers: weak 3-10, medium 15-25, strong 30-40.

const T = {
    LONG_URL: 75,
    LONG_HOST: 30,
    MANY_SUBDOMAINS: 3,
    MANY_HYPHENS: 2,
    HOST_DIGIT_RATIO: 0.2,
    DOMAIN_ENTROPY: 3.5,
    ENCODED_CHARS: 5,
};

const RISKY_EXTENSIONS = new Set([
    "exe", "apk", "scr", "msi", "bat", "cmd", "jar", "vbs", "iso", "zip", "rar",
]);

const hasAnyKeyword = (f) =>
    f.hostKeywords.length > 0 || f.pathKeywords.length > 0 || f.queryKeywords.length > 0;

export const RULES = [
    // Strong: almost never legitimate
    {
        id: "R_USERINFO_DOMAIN",
        weight: 40,
        description: "The part before the @ looks like a domain (e.g. paypal.com@evil.xyz), hiding the real destination.",
        test: (f) => f.hasUserInfo && f.userInfoLooksLikeDomain,
    },
    {
        id: "R_IP_HOST",
        weight: 35,
        description: "The address is a raw IP number instead of a domain name.",
        test: (f) => f.isIpHost,
    },
    {
        id: "R_TLD_IN_SUBDOMAIN",
        weight: 35,
        description: "A domain ending such as .com appears inside the subdomain, imitating another site.",
        test: (f) => f.subdomainHasTld,
    },

    // Medium: unusual, but with legitimate uses
    {
        id: "R_SHARED_HOSTING_KEYWORD",
        weight: 25,
        description: "A sensitive keyword on a free shared-hosting domain that anyone can register.",
        test: (f) => f.isSharedHosting && hasAnyKeyword(f),
    },
    {
        id: "R_RISKY_EXTENSION",
        weight: 20,
        description: "The link points straight to an executable or archive file.",
        test: (f) => RISKY_EXTENSIONS.has(f.pathExtension),
    },
    {
        id: "R_PUNYCODE",
        weight: 20,
        description: "The domain uses international characters that can imitate familiar letters.",
        test: (f) => f.isPunycode,
    },
    {
        id: "R_KEYWORD_NO_HTTPS",
        weight: 20,
        description: "A sensitive keyword on a connection that isn't encrypted.",
        test: (f) => !f.hasHttps && hasAnyKeyword(f),
    },
    {
        id: "R_HOST_KEYWORD",
        weight: 15,
        description: "The domain name contains a sensitive word such as login, verify or secure.",
        test: (f) => f.hostKeywords.length >= 1,
    },
    {
        id: "R_HOST_KEYWORDS_MULTI",
        weight: 15,
        description: "The domain name contains several sensitive words.",
        test: (f) => f.hostKeywords.length >= 2,
    },
    {
        id: "R_MANY_SUBDOMAINS",
        weight: 15,
        description: "Unusually deep subdomain nesting.",
        test: (f) => f.subdomainCount >= T.MANY_SUBDOMAINS,
    },
    {
        id: "R_MANY_HYPHENS",
        weight: 15,
        description: "Two or more hyphens in the domain name.",
        test: (f) => f.numHyphens >= T.MANY_HYPHENS,
    },
    {
        id: "R_LONG_HOST",
        weight: 15,
        description: "The domain name is unusually long.",
        test: (f) => f.hostLength > T.LONG_HOST,
    },
    {
        id: "R_QUERY_HAS_URL",
        weight: 15,
        description: "Another web address is embedded in the link, a common redirect trick.",
        test: (f) => f.queryHasUrl,
    },

    // Weak: common on legitimate sites, useful only in combination
    {
        id: "R_HIGH_DIGIT_HOST",
        weight: 10,
        description: "A large share of the domain name is digits.",
        test: (f) => f.hostDigitRatio > T.HOST_DIGIT_RATIO,
    },
    {
        id: "R_RANDOM_DOMAIN",
        weight: 10,
        description: "The domain name looks randomly generated.",
        test: (f) => f.domainEntropy > T.DOMAIN_ENTROPY,
    },
    {
        id: "R_SHORTENER",
        weight: 10,
        description: "A link shortener hides the real destination.",
        test: (f) => f.isShortener,
    },
    {
        id: "R_ENCODED_CHARS",
        weight: 10,
        description: "Many percent-encoded characters, which can disguise the address.",
        test: (f) => f.numEncodedChars >= T.ENCODED_CHARS,
    },
    {
        id: "R_ODD_PORT",
        weight: 10,
        description: "The link uses a non-standard port number.",
        test: (f) => f.hasPortNumber,
    },
    {
        id: "R_NO_HTTPS",
        weight: 8,
        description: "The connection is not encrypted.",
        test: (f) => !f.hasHttps,
    },
    {
        id: "R_LONG_URL",
        weight: 8,
        description: "The full address is unusually long.",
        test: (f) => f.urlLength > T.LONG_URL,
    },
    {
        id: "R_ONE_HYPHEN",
        weight: 5,
        description: "A hyphen in the domain name.",
        test: (f) => f.numHyphens === 1,
    },
    {
        id: "R_PATH_KEYWORD",
        weight: 5,
        description: "A sensitive word appears in the path or query.",
        test: (f) => f.pathKeywords.length > 0 || f.queryKeywords.length > 0,
    },
];