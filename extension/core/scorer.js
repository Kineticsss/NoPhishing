import { RULES } from "./rules.js";
import { extractFeatures } from "./urlFeatures.js";

// Placeholder cutoffs. Tune them with scripts/evaluate.js once it exists.
export const THRESHOLDS = { WARN: 30, BLOCK: 60 };
export const MAX_SCORE = 100;

export function verdictFor(score) {
    if (score >= THRESHOLDS.BLOCK) return "blocked";
    if (score >= THRESHOLDS.WARN) return "warn";
    return "allow";
}

// options.rules: custom rule list (defaults to RULES)
// options.skipRules: rule ids to ignore, e.g. the HTTPS rules for datasets with no scheme
export function scoreFeatures(features, { rules = RULES, skipRules = [] } = {}) {
    if (!features || !features.analyzable) {
        return {
            analyzable: false,
            reason: features?.reason ?? "no_features",
            score: 0,
            rawScore: 0,
            verdict: "unanalyzable",
            rules_fired: [],
            errors: [],
        };
    }

    const skip = new Set(skipRules);
    const rules_fired = [];
    const errors = [];

    for (const rule of rules) {
        if (skip.has(rule.id)) continue;
        try {
            if (rule.test(features) === true) {
                rules_fired.push({ id: rule.id, weight: rule.weight });
            }
        } catch (err) {
            // One broken rule must never take down a scan.
            errors.push({ id: rule.id, message: String(err) });
        }
    }

    const rawScore = rules_fired.reduce((sum, r) => sum + r.weight, 0);
    const score = Math.min(MAX_SCORE, rawScore);

    return { analyzable: true, score, rawScore, verdict: verdictFor(score), rules_fired, errors };
}

export function scoreUrl(rawUrl, options) {
    return scoreFeatures(extractFeatures(rawUrl), options);
}