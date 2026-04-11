# OrbWeaver FrothIQ

> **OrbWeaver** · [orbweaver.com](https://orbweaver.com)

---

Bar and beverage management tools built on Frappe.

SEO Optimization & Insights Tool

### Installation

You can install this app using the [bench](https://github.com/frappe/bench) CLI:

```bash
cd $PATH_TO_YOUR_BENCH
bench get-app $URL_OF_THIS_REPO --branch main
bench install-app frothiq
```

### Contributing

This app uses `pre-commit` for code formatting and linting. Please [install pre-commit](https://pre-commit.com/#installation) and enable it for this repository:

```bash
cd apps/frothiq
pre-commit install
```

Pre-commit is configured to use the following tools for checking and formatting your code:

- ruff
- eslint
- prettier
- pyupgrade
### CI

This app can use GitHub Actions for CI. The following workflows are configured:

- CI: Installs this app and runs unit tests on every push to `develop` branch.
- Linters: Runs [Frappe Semgrep Rules](https://github.com/frappe/semgrep-rules) and [pip-audit](https://pypi.org/project/pip-audit/) on every pull request.


### License

All Rights Reserved

Frothiq – SEO Application Feature List

# SEO Overview Module  
Dashboard & Global Scoring System

- SEO Score calculation (0–100)

- Category breakdown:
  - On-Page SEO Score
  - Technical SEO Score
  - Off-Page SEO Score
  - Social Media Score

- Issue detection system:
  - Critical Issues counter
  - Minor Issues counter

- Page summary view for each Web Page


# On-Page SEO Module

- Tools that evaluate content & structure:

  - **Title & Metadata Tools**
    - Missing title detector
    - Title length validator (50–60 chars)
    - Missing meta description detector
    - Meta description length validator (100–130 chars)

  - **Heading Structure Tools**
    - Missing H1 detection
    - H1 length validator (10–70 chars)
    - Full H2–H6 structure analyzer
    - Heading hierarchy validator (detect skips/gaps)
    - Overuse/underuse of headings

  - **Content Analysis Tools**
    - Word count analysis
    - Thin content alerts (< 500 words)
    - Text-to-code ratio calculator
    - Code bloat detection

  - **Media Tools**
    - Image Alt text checker
    - Image count / audit report

  - **Keyword Tools**
    - Keyword density analyzer
    - Keyword extraction for the page
    - Highest-density keyword report

  - **URL Tools**
    - URL length validator
    - URL formatting checker


# Keyword Rankings Module

- Extract top organic keywords
- Rank tracker
- Keyword difficulty (KD %)
- Search volume display
- CPC estimation
- Click distribution estimation
- Keyword opportunity suggestions


# Top Pages Module

- Page ranking by traffic
- Keywords per page
- Referring domains per page
- Backlinks per page
- Page authority indicator


# Technical SEO Module

- **Core HTML & Tag Structure**
  - Favicon checker
  - Language declaration checker (`<html lang="">`)
  - Canonical tag validator
    - Missing canonical
    - Multiple canonicals
    - Broken canonical URL

- **Crawlability & Indexing**
  - Noindex / Nofollow detection
  - Robots.txt validator
  - Accessibility check
  - Syntax validation
  - Sitemap validator
    - Check active XML sitemap
    - Display sitemap location

- **Internationalization Tools**
  - Hreflang validator
  - Multi-region language checks

- **Structured Data Tools**
  - Schema markup detector
  - Schema error validator
  - Google Rich Results compatibility report


# Page Speed & Core Web Vitals Module

- (Uses PageSpeed API or internal scorer)

- **Performance Metrics**
  - Performance score (mobile & desktop)
  - Mobile-friendliness checker
  - Responsive viewport detection
  - Tap target spacing validator
  - Font size accessibility validator

- **Core Web Vitals**
  - LCP (Largest Contentful Paint)
  - FCP (First Contentful Paint)
  - CLS (Cumulative Layout Shift)
  - INP (Interaction to Next Paint)
  - TBT (Total Blocking Time)
  - TTFB (Time To First Byte)
  - Speed Index
  - DOM Size evaluator


# Competitor Analysis Module

- Auto-detect competitor domains
- Keyword overlap calculator
- Competition level score
- Shared keyword tracking


# Off-Page SEO Module

- **Backlink Audit Tools**
  - Top backlinks list
  - Referring domains count
  - Authority score for linking sites
  - DoFollow / NoFollow identification

- **Brand Mentions**
  - External site mentions
  - Citation authority


# Social Media Presence Module

- Social link detection & validation:
  - Facebook
  - YouTube
  - Instagram
  - X (Twitter)
  - LinkedIn

- Checks include:
  - Missing links
  - Broken links
  - Incorrect URL structure
  - Inactive pages


# System & Utility Tools

- API connection health checker
- DOM retrieval fallback handler
- Error logging for inaccessible pages
- Local & remote scanning modes
- Automated “Fix Recommendations” generator


“Fix Recommendations” generator
