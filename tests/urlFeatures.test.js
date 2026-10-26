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