# SecureSight — Content Extraction Engine

> Historical document from before remediation. Old feature counts, model metrics, label conversions, transport/sandbox claims and completion statements are superseded by [verified current behavior](REMEDIATION_20261008.md). Active model/schema: 5.1.1; 97 fields, with 59 URL fields actually learned. Do not use this historical document as a public-readiness claim.

## Overview
The Content Extraction module (`utils/content_nlp.py`) extracts clean, visible body text from remote webpage HTML while stripping non-content elements (`<script>`, `<style>`, `<noscript>`).

## Text Extraction Pipeline
1. Parse HTML via BeautifulSoup.
2. Remove scripts, inline styles, and noscript elements.
3. Extract visible text from body, headings (`<h1>`-`<h6>`), paragraphs, form labels, and buttons.
4. Normalize whitespace and split into clean text chunks.
5. Generate visible text snippet (up to 150 characters) for explainable evidence reporting.

## Privacy & Data Minimization
- The full webpage HTML is NOT permanently stored in memory or databases.
- Sensitive user inputs, password values, tokens, and cookies are never captured or recorded.
