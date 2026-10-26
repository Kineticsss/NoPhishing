import { test } from "node:test";
import assert from "node:assert/strict";
import { parseHost } from "../extension/core/psl.js";

test("plain .com", () => {
    const r = parseHost("www.example.com");
    assert.equal(r.publicSuffix, "com");
    assert.equal(r.registeredDomain, "example.com");
    assert.equal(r.subdomainCount, 1);
    assert.equal(r.isSharedHosting, false);
});

test("multi-part suffix co.uk", () => {
    const r = parseHost("www.example.co.uk");
    assert.equal(r.publicSuffix, "co.uk");
    assert.equal(r.registeredDomain, "example.co.uk");
    assert.equal(r.subdomainCount, 1);
});

test("com.ph", () => {
    const r = parseHost("a.b.com.ph");
    assert.equal(r.publicSuffix, "com.ph");
    assert.equal(r.registeredDomain, "b.com.ph");
    assert.equal(r.subdomainCount, 1);
});

test("shared hosting github.io", () => {
    const r = parseHost("foo.github.io");
    assert.equal(r.publicSuffix, "github.io");
    assert.equal(r.registeredDomain, "foo.github.io");
    assert.equal(r.subdomainCount, 0);
    assert.equal(r.isSharedHosting, true);
});

test("wildcard and exception rules (*.ck, !www.ck)", () => {
    assert.equal(parseHost("a.b.ck").publicSuffix, "b.ck");
    assert.equal(parseHost("www.ck").publicSuffix, "ck");
    assert.equal(parseHost("www.ck").registeredDomain, "www.ck");
});

test("host that is only a suffix", () => {
    assert.equal(parseHost("co.uk").registeredDomain, null);
});

test("unknown TLD falls back to the last label", () => {
    const r = parseHost("example.notarealtld");
    assert.equal(r.publicSuffix, "notarealtld");
    assert.equal(r.registeredDomain, "example.notarealtld");
});

test("trailing dot is ignored", () => {
    assert.equal(parseHost("example.com.").registeredDomain, "example.com");
});