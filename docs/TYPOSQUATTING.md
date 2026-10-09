# Typosquatting and Unicode

`app/brand/similarity.py` implements Levenshtein distance and Jaro-Winkler similarity, plus insertion, deletion, substitution, adjacent transposition, hyphenation, digit insertion and brand-token prefix/suffix patterns. Inputs are bounded to 253 characters; reported comparisons are capped at 32.

Compare the registrable label with registry aliases, excluding unrelated subdomain words. Preserve original hostname, Unicode decoding, normalized/Punycode hostname and the NFKC/casefold confusable skeleton. No raw path or query is exposed.

Confusable mapping covers selected common Cyrillic and Greek lookalikes. This is not a complete Unicode TR39 database or a visual/OCR comparison. Most legitimate IDNs produce no confusable brand finding. Similarity itself is unscored; a close typo needs independently applicable credential context and multiple page fields to qualify the existing BRAND signal. Brand token prefix/suffix alone does not satisfy that close-typo requirement.

Fixtures cover spelling operations, known Jaro-Winkler values, input caps, Cyrillic PayPal lookalikes and benign international bookstore names.
