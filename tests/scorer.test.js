import { test } from "node:test";
import assert from "node:assert/strict";
import { scoreUrl, scoreFeatures, verdictFor, MAX_SCORE } from "../extension/core/scorer.js";
import { RULES } from "../extension/core/rules.js";

test("benign site is allowed with score 0", () => {
    const r = scoreUrl("https://www.wikipedia.org/");
    assert.equal(r.score, 0);
    assert.equal(r.verdict, "allow");
    assert.deepEqual(r.rules_fired, []);
});

test("IP host lands in warn", () => {
    const r = scoreUrl("http://192.168.0.1/admin");
    assert.equal(r.verdict, "warn");
    assert.ok(r.rules_fired.some((x) => x.id === "R_IP_HOST"));
});

test("brand in subdomain plus login path is blocked", () => {
    const r = scoreUrl("http://paypal.com.evil.xyz/login");
    assert.equal(r.verdict, "blocked");
    assert.ok(r.score >= 60);
});

test("rules_fired has the {id, weight} shape", () => {
    const r = scoreUrl("http://192.168.0.1/admin");
    for (const x of r.rules_fired) {
        assert.equal(typeof x.id, "string");
        assert.equal(typeof x.weight, "number");
    }
});

test("skipRules removes a rule from the score", () => {
    const full = scoreUrl("http://192.168.0.1/admin");
    const skipped = scoreUrl("http://192.168.0.1/admin", { skipRules: ["R_NO_HTTPS"] });
    assert.ok(!skipped.rules_fired.some((x) => x.id === "R_NO_HTTPS"));
    assert.equal(skipped.score, full.score - RULES.find((r) => r.id === "R_NO_HTTPS").weight);
});

test("score is capped at 100 but rawScore is kept", () => {
    const heavy = [
        { id: "R_A", weight: 70, description: "a", test: () => true },
        { id: "R_B", weight: 70, description: "b", test: () => true },
    ];
    const r = scoreFeatures({ analyzable: true }, { rules: heavy });
    assert.equal(r.score, MAX_SCORE);
    assert.equal(r.rawScore, 140);
});

test("a throwing rule is recorded and does not crash the scan", () => {
    const rules = [
        { id: "R_BAD", weight: 10, description: "x", test: () => { throw new Error("boom"); } },
        { id: "R_OK", weight: 10, description: "y", test: () => true },
    ];
    const r = scoreFeatures({ analyzable: true }, { rules });
    assert.equal(r.errors.length, 1);
    assert.equal(r.errors[0].id, "R_BAD");
    assert.equal(r.score, 10);
});

test("unanalyzable input scores 0 with a reason", () => {
    const r = scoreUrl("chrome://settings");
    assert.equal(r.analyzable, false);
    assert.equal(r.verdict, "unanalyzable");
    assert.equal(r.reason, "unsupported_protocol");
});

test("verdict boundaries", () => {
    assert.equal(verdictFor(29), "allow");
    assert.equal(verdictFor(30), "suspicious");
    assert.equal(verdictFor(39), "suspicious");
    assert.equal(verdictFor(40), "warn");
    assert.equal(verdictFor(59), "warn");
    assert.equal(verdictFor(60), "blocked");
});

test("rules in the same group are capped", () => {
    const rules = [
        { id: "R_A", weight: 30, group: "host_structure", description: "a", test: () => true },
        { id: "R_B", weight: 30, group: "host_structure", description: "b", test: () => true },
        { id: "R_C", weight: 5, description: "c", test: () => true },
    ];
    const r = scoreFeatures({ analyzable: true }, { rules });
    assert.equal(r.rawScore, 65);
    assert.equal(r.score, 45); // 40 (capped group) + 5
});