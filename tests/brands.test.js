import { test } from "node:test";
import assert from "node:assert/strict";
import { BRANDS } from "../extension/core/data/brands.js";

test("brand list is clean", () => {
    const names = new Set();
    for (const b of BRANDS) {
        assert.equal(b.name, b.name.toLowerCase());
        assert.ok(!names.has(b.name), `duplicate brand ${b.name}`);
        names.add(b.name);
        for (const d of b.domains ?? []) assert.equal(d, d.toLowerCase());
    }
});