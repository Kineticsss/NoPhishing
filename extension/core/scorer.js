import { RULES } from "./rules.js";
import { extractFeatures } from "./urlFeatures.js";


export const GROUP_CAPS = { host_structure: 40, keywords: 35, brand: 35, hosting: 25 };

// Placeholder cutoffs. Tune them with scripts/evaluate.js once it exists.
export const MAX_SCORE = 100;
export const THRESHOLDS = { LOG: 30, WARN: 40, BLOCK: 60 };

export function verdictFor(score) {
    if (score >= THRESHOLDS.BLOCK) return "blocked";
    if (score >= THRESHOLDS.WARN) return "warn";
    if (score >= THRESHOLDS.LOG) return "suspicious"; // recorded as an event, no gate
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
    const groupSums = {};
    let ungrouped = 0;
    let rawScore = 0;

    for (const rule of rules) {
        if (skip.has(rule.id)) continue;
        try {
            if (rule.test(features) === true) {
                rules_fired.push({ id: rule.id, weight: rule.weight });
                rawScore += rule.weight;
                if (rule.group) groupSums[rule.group] = (groupSums[rule.group] ?? 0) + rule.weight;
                else ungrouped += rule.weight;
            }
        } catch (err) {
            errors.push({ id: rule.id, message: String(err) });
        }
    }

    // Rules in one group measure the same thing, so a group can add only up to its cap.
    let total = ungrouped;
    for (const [group, sum] of Object.entries(groupSums)) {
        total += Math.min(sum, GROUP_CAPS[group] ?? sum);
    }
    const score = Math.min(MAX_SCORE, total);

    return { analyzable: true, score, rawScore, verdict: verdictFor(score), rules_fired, errors };
}

export function scoreUrl(rawUrl, options) {
    return scoreFeatures(extractFeatures(rawUrl), options);
}