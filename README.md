# NoPhishing

A local-first anti-phishing browser extension. Every URL it scans becomes a structured, SIEM-style event that you can search with an SPL-style query language. When a page looks risky, a gate offers **Close**, **Continue anyway**, or **Investigate further**.

> **Status: early development.** The scoring core is being built and tested in Node. The browser extension itself (manifest, gate, dashboard) has not been written yet.

## Planned features

- Scan URLs and emails and turn each scan into an event with a score, a verdict, the rules that fired, and the extracted features.
- Search past events with SPL-style queries, for example:
  `verdict=blocked score>70 tld=xyz | stats count by rule | sort -count | head 10`
- A warning gate with three choices: Close, Continue anyway, or Investigate further. The last opens a breakdown of why the page was flagged, with a one-click pivot to related events.
- Email scanning by parsing `.eml` files (headers, SPF/DKIM/DMARC results, links).
- Everything stays on your machine. No URLs are sent anywhere. Any online lookups added later will be opt-in.

## How it works

```
URL -> extractFeatures -> rules -> scorer -> event -> gate / dashboard
```

1. **`urlFeatures.js`** parses a URL into features: lengths, host structure, keywords, entropy, embedded URLs, and more.
2. **`psl.js`** uses the Public Suffix List to find the real registered domain, so `www.example.co.uk` and `foo.github.io` are handled correctly.
3. **`rules.js`** holds small rules, each with an `id`, a `weight`, a human-readable `description`, and a `test(features)` function.
4. **`scorer.js`** (next) adds up the weights of the rules that fired, caps the score at 100, and picks a verdict.
5. **`event.js`** (planned) packages everything into the event that the gate, the investigation view, and the query engine all read.

## Progress

| Part | State |
|---|---|
| Public Suffix List matcher (`psl.js`) | Done, tested |
| URL feature extractor (`urlFeatures.js`) | Done, tested |
| Detection rules (`rules.js`) | Drafted, weights are untuned guesses |
| Scorer (`scorer.js`) | Next |
| Evaluation scripts and dataset loaders | Planned |
| Brand lookalike detection | Planned |
| Event builder, event store | Planned |
| Query engine | Planned |
| Email parser | Planned |
| Extension shell (Manifest V3, gate, investigate, dashboard) | Planned |

## Project layout

```
NoPhishing/
├── package.json
├── tests/                     Node tests
├── scripts/                   evaluation scripts (planned)
├── data-raw/                  evaluation datasets (gitignored, never committed)
└── extension/                 the folder you will load unpacked in Chrome
    └── core/                  pure JavaScript, no browser APIs
        ├── urlFeatures.js
        ├── psl.js
        ├── rules.js
        └── data/
            └── publicSuffixList.js
```

More files will be added under `core/`, `storage/`, `gate/`, `investigate/`, `dashboard/`, and `content/` as the extension takes shape.

## Getting started

Requires Node.js 18 or newer.

```
npm test
```

Run a single test file with `node --test tests/psl.test.js`.

## Evaluation data

The datasets are **not** included in this repository. Download them yourself and place them in `data-raw/`, which is gitignored. Some things to know before using them:

- **Label coding differs between files.** Some use 1 for phishing, others use 0. Always map labels explicitly.
- **Several sets have built-in bias.** In some, the legitimate URLs are all bare homepages, so path and length rules look better than they really are. Others have no scheme, so HTTPS rules can't be evaluated on them.
- **Some "malicious" sets are mostly malware URLs**, not phishing.
- Test across more than one dataset, and split by registered domain so the same domain never appears on both sides.
- Check each dataset's license before redistributing anything.

## Known limitations

- Rule weights are starting guesses and have not been tuned on data yet.
- The keyword rules will flag some legitimate sites until brand allowlisting is added.
- Available datasets are generic and contain very little Philippines-specific phishing, so real-world accuracy for local brands is unknown.
- The Public Suffix List is a snapshot. Update it periodically (the download date is noted at the top of `publicSuffixList.js`).

## License

Not yet chosen.