import { test } from "node:test";
import assert from "node:assert/strict";
import { normalizeUrl, DATASETS } from "../scripts/loaders.js";

test("keeps URLs that already have a scheme", () => {
    assert.deepEqual(normalizeUrl(" https://a.com/x "), { url: "https://a.com/x", schemeKnown: true });
});

test("adds http:// and flags a missing scheme", () => {
    assert.deepEqual(normalizeUrl("a.com/login"), { url: "http://a.com/login", schemeKnown: false });
    assert.deepEqual(normalizeUrl("a.com:8080/x"), { url: "http://a.com:8080/x", schemeKnown: false });
});

test("empty input returns null", () => {
    assert.equal(normalizeUrl("   "), null);
    assert.equal(normalizeUrl(undefined), null);
});

test("label mappings are not mixed up between datasets", () => {
    assert.equal(DATASETS.dataset.mapLabel("1"), "phish");
    assert.equal(DATASETS.phiusiil.mapLabel("1"), "legit"); // reversed on purpose
    assert.equal(DATASETS.phiusiil.mapLabel("0"), "phish");
    assert.equal(DATASETS.siteurls.mapLabel("bad"), "phish");
    assert.equal(DATASETS.dataset.mapLabel("2"), null);
});