import { test } from "node:test";
import assert from "node:assert/strict";
import { RULES } from "../extension/core/rules.js";
import { extractFeatures } from "../extension/core/urlFeatures.js";

const fired = (url) => {
    const f = extractFeatures(url);
    return RULES.filter((r) => r.test(f)).map((r) => r.id);
};

test("every rule is well-formed with a unique id", () => {
    const ids = new Set();
    for (const r of RULES) {
        assert.match(r.id, /^R_[A-Z0-9_]+$/);
        assert.ok(!ids.has(r.id), `duplicate id ${r.id}`);
        ids.add(r.id);
        assert.ok(r.weight > 0 && r.description.length > 0);
        assert.equal(typeof r.test, "function");
    }
});

test("every rule returns a real boolean on real features", () => {
    const urls = [
        "https://www.wikipedia.org/",
        "http://192.168.0.1/admin",
        "http://paypal.com.evil.xyz/login?next=http://x.com",
    ];
    for (const u of urls) {
        const f = extractFeatures(u);
        for (const r of RULES) {
            assert.equal(typeof r.test(f), "boolean", `${r.id} on ${u}`);
        }
    }
});

test("benign site fires nothing", () => {
    assert.deepEqual(fired("https://www.wikipedia.org/"), []);
});

test("IP host fires R_IP_HOST and R_NO_HTTPS", () => {
    const ids = fired("http://192.168.0.1/admin");
    assert.ok(ids.includes("R_IP_HOST") && ids.includes("R_NO_HTTPS"));
});

test("brand in subdomain fires R_TLD_IN_SUBDOMAIN", () => {
    assert.ok(fired("http://paypal.com.evil.xyz/login").includes("R_TLD_IN_SUBDOMAIN"));
});

test("domain-looking username fires R_USERINFO_DOMAIN", () => {
    assert.ok(fired("http://paypal.com@evil.xyz/").includes("R_USERINFO_DOMAIN"));
});

test("keyword on shared hosting fires R_SHARED_HOSTING_KEYWORD", () => {
    assert.ok(fired("https://login-paypal.pages.dev/").includes("R_SHARED_HOSTING_KEYWORD"));
});