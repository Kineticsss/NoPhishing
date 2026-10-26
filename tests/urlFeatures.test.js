import { test } from "node:test";
import assert from "node:assert/strict";
import { extractFeatures } from "../extension/core/urlFeatures.js";

test("rejects bad input with a reason", () => {
    assert.deepEqual(extractFeatures("not a url"), { analyzable: false, reason: "invalid_url" });
    assert.equal(extractFeatures("ftp://x.com").reason, "unsupported_protocol");
});

test("decodes percent-encoded keywords", () => {
    const f = extractFeatures("http://x.com/%6Cogin");
    assert.deepEqual(f.pathKeywords, ["login"]);
    assert.equal(f.numEncodedChars, 1);
});

test("detects a URL embedded in the query", () => {
    assert.equal(extractFeatures("http://x.com/?next=http://evil.com").queryHasUrl, true);
    assert.equal(extractFeatures("http://x.com/?a=1").queryHasUrl, false);
});

test("strips the trailing dot from the host", () => {
    assert.equal(extractFeatures("http://example.com./").host, "example.com");
});

test("multi-part suffix is handled through the PSL", () => {
    const f = extractFeatures("http://www.example.co.uk/");
    assert.equal(f.tld, "uk");
    assert.equal(f.publicSuffix, "co.uk");
    assert.equal(f.registeredDomain, "example.co.uk");
    assert.equal(f.subdomainCount, 1);
});

test("brand in a subdomain is not the registered domain", () => {
    const f = extractFeatures("http://paypal.com.evil.xyz/login");
    assert.equal(f.registeredDomain, "evil.xyz");
    assert.equal(f.subdomain, "paypal.com");
    assert.equal(f.subdomainCount, 2);
});

test("shared hosting is flagged", () => {
    const f = extractFeatures("https://login-paypal.pages.dev/");
    assert.equal(f.isSharedHosting, true);
    assert.equal(f.registeredDomain, "login-paypal.pages.dev");
});

test("IP hosts have no domain structure", () => {
    const f = extractFeatures("http://192.168.0.1/admin");
    assert.equal(f.isIpHost, true);
    assert.equal(f.tld, null);
    assert.equal(f.registeredDomain, null);
    assert.equal(f.subdomainCount, 0);
});

test("keywords must sit on token boundaries", () => {
    assert.deepEqual(extractFeatures("http://microdesigninformatica.com.br/").hostKeywords, []);
    assert.deepEqual(extractFeatures("http://paypalverify.com/").hostKeywords, ["verify"]);
});

test("punycode hosts do not inflate hyphen, digit or entropy features", () => {
    const f = extractFeatures("http://xn--80ajk9a.xn--80acgfbsl1azdqr.xn--p1ai/");
    assert.equal(f.isPunycode, true);
    assert.equal(f.numHyphens, 0);
    assert.equal(f.hostDigitRatio, 0);
    assert.equal(f.domainEntropy, 0);
});

test("weak keywords are not counted as strong", () => {
    const f = extractFeatures("http://savings-account-interest-rates.blogspot.com/");
    assert.deepEqual(f.hostKeywords, ["account"]);
    assert.deepEqual(f.hostStrongKeywords, []);
    assert.equal(f.hasStrongKeyword, false);
});

test("plain info. subdomains are not fake TLDs", () => {
    assert.equal(extractFeatures("http://info.example.org/").subdomainHasTld, false);
    assert.equal(extractFeatures("http://www.info.example.it/").subdomainHasTld, false);
    assert.equal(extractFeatures("http://paypal.com.evil.xyz/").subdomainHasTld, true);
});

test("brand in the subdomain of an unrelated domain", () => {
    assert.deepEqual(extractFeatures("http://paypal.com.evil.xyz/").brandsInSubdomain, ["paypal"]);
});

test("official brand domains are not flagged", () => {
    for (const u of ["https://www.paypal.com/signin", "https://docs.google.com/", "https://www.google.co.uk/", "https://outlook.office.com/mail"]) {
        const f = extractFeatures(u);
        assert.deepEqual(f.brandsInSubdomain, [], u);
        assert.deepEqual(f.brandsInPath, [], u);
    }
});

test("brand names on shared hosting count as impersonation", () => {
    assert.deepEqual(extractFeatures("https://login-paypal.pages.dev/").brandsInSubdomain, ["paypal"]);
    assert.deepEqual(extractFeatures("https://paypal.github.io/").brandsInSubdomain, ["paypal"]);
});

test("brand as a folder in the path", () => {
    assert.deepEqual(extractFeatures("http://kosarcd.com/data/paypal/index.html").brandsInPath, ["paypal"]);
    assert.deepEqual(extractFeatures("http://x.com/wp-admin/WellsFargo/present.php").brandsInPath, ["wellsfargo"]);
    assert.deepEqual(extractFeatures("http://mail.printakid.com/www.online.americanexpress.com/index.html").brandsInPath, ["americanexpress"]);
});

test("brand words inside a long article slug are ignored", () => {
    assert.deepEqual(extractFeatures("http://blog.litl.com/2009/12/03/introducing-the-new-facebook-status-channel/").brandsInPath, []);
});

test("random-looking label on shared hosting", () => {
    assert.equal(extractFeatures("https://hidok4f8zl.firebaseapp.com/").sharedHostRandomLabel, true);
    assert.equal(extractFeatures("https://my-travel-blog.firebaseapp.com/").sharedHostRandomLabel, false);
    assert.equal(extractFeatures("https://hidok4f8zl.example.com/").sharedHostRandomLabel, false);
});