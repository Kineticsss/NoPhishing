// Weights are starting guesses, adjusted using scripts/evaluate.js results across three datasets.
// Tiers: weak 3-10, medium 15-25, strong 30-40.
//
// "group" marks rules that measure the same underlying fact. The scorer caps each group
// (see GROUP_CAPS in scorer.js) so one fact is not counted several times.

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
        group: "host_structure",
        weight: 35,
        description: "A domain ending such as .com appears inside the subdomain, imitating another site.",
        test: (f) => f.subdomainHasTld,
    },

    // Medium: unusual, but with legitimate uses
    {
        id: "R_SHARED_HOSTING_KEYWORD",
        group: "keywords",
        weight: 25,
        description: "A sensitive keyword on a free shared-hosting domain that anyone can register.",
        test: (f) => f.isSharedHosting && (f.hasStrongKeyword || f.hostKeywords.length >= 2),
    },
    {
        id: "R_RISKY_EXTENSION",
        weight: 20,
        description: "The link points straight to an executable or archive file.",
        test: (f) => RISKY_EXTENSIONS.has(f.pathExtension),
    },
    {
        id: "R_KEYWORD_NO_HTTPS",
        group: "keywords",
        weight: 20,
        description: "A sensitive keyword on a connection that isn't encrypted.",
        test: (f) => !f.hasHttps && hasAnyKeyword(f),
    },
    {
        id: "R_HOST_KEYWORD",
        group: "keywords",
        weight: 15,
        description: "The domain name contains a sensitive word such as login, verify or secure.",
        test: (f) => f.hostStrongKeywords.length >= 1,
    },
    {
        id: "R_HOST_KEYWORDS_MULTI",
        group: "keywords",
        weight: 15,
        description: "The domain name contains several sensitive words.",
        test: (f) => f.hostKeywords.length >= 2,
    },
    {
        id: "R_MANY_SUBDOMAINS",
        group: "host_structure",
        weight: 15,
        description: "Unusually deep subdomain nesting.",
        test: (f) => f.subdomainCount >= T.MANY_SUBDOMAINS,
    },
    {
        id: "R_MANY_HYPHENS",
        group: "host_structure",
        weight: 15,
        description: "Two or more hyphens in the domain name.",
        test: (f) => f.numHyphens >= T.MANY_HYPHENS,
    },
    {
        id: "R_LONG_HOST",
        group: "host_structure",
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
        id: "R_PUNYCODE",
        weight: 10,
        description: "The domain uses international characters that can imitate familiar letters.",
        test: (f) => f.isPunycode,
    },
    {
        id: "R_HIGH_DIGIT_HOST",
        group: "host_structure",
        weight: 10,
        description: "A large share of the domain name is digits.",
        test: (f) => f.hostDigitRatio > T.HOST_DIGIT_RATIO,
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
        id: "R_PATH_KEYWORD",
        group: "keywords",
        weight: 5,
        description: "A sensitive word appears in the path or query.",
        test: (f) => f.pathKeywords.length > 0 || f.queryKeywords.length > 0,
    },
    {
        id: "R_LONG_URL",
        weight: 4,
        description: "The full address is unusually long.",
        test: (f) => f.urlLength > T.LONG_URL,
    },
    {
        id: "R_BRAND_IN_SUBDOMAIN",
        group: "brand",
        weight: 30,
        description: "A well-known brand name appears in the subdomain of a site that isn't that brand's.",
        test: (f) => f.brandsInSubdomain.length > 0,
    },
    {
        id: "R_BRAND_IN_PATH",
        group: "brand",
        weight: 20,
        description: "A well-known brand name appears as a folder or file in the path of a site that isn't that brand's.",
        test: (f) => f.brandsInPath.length > 0,
    },
    {
        id: "R_SHARED_HOSTING",
        group: "hosting",
        weight: 10,
        description: "The site is hosted on a free platform where anyone can create a page. Common for phishing, but also for honest hobby sites.",
        test: (f) => f.isSharedHosting,
    },
    {
        id: "R_SHARED_HOSTING_RANDOM",
        group: "hosting",
        weight: 20,
        description: "A random-looking name on a free hosting platform, typical of throwaway phishing pages.",
        test: (f) => f.sharedHostRandomLabel,
    },
    {
        id: "R_NO_HTTPS",
        weight: 3,
        description: "The connection is not encrypted. Weak on its own, since most phishing now uses HTTPS too.",
        test: (f) => !f.hasHttps,
    },
    {
        id: "R_HOST_KEYWORD_WEAK",
        group: "keywords",
        weight: 5,
        description: "The domain name contains a generic word such as account or update.",
        test: (f) => f.hostKeywords.length >= 1 && f.hostStrongKeywords.length === 0,
    },
];