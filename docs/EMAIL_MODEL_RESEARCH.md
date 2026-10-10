# Experimental email model card

`email-research-v1` is a research-only phishing-pattern estimator. It uses eight aggregate handcrafted features (message length, word count, keyword hits, URL count, punctuation counts, digit count and character entropy) extracted from email subject/body text. It does not understand language semantically, authenticate the sender, or inspect attachment contents. The scanner's observable evidence and linked-site checks remain separate.

The model is calibrated on a dedicated split and selected with grouped cross-validation. On the held-out grouped test partition (32,840 messages), it achieved ROC AUC 0.924, precision 98.0%, recall 50.4%, false-positive rate 1.13% at the stored alert threshold 0.9364. It missed 8,522 of 17,169 phishing-labeled test emails. These historical benchmark results do not establish current deployment accuracy or generalization to new campaigns.

The user interface labels the value an **experimental estimate**, not a correctness probability. Crossing the high alert threshold adds a warning; staying below it never yields a legitimate/safe verdict. The interface tells users that the model misses phishing emails.

The model file is SHA-256 checked before deserialization. Expected digest: `24a3626899539b819504ca6b144e76cc4f8f7f82b65fe4921819ae805d5a4b02`.

## Open review items

- Licenses for all training sources and redistribution of this derived artifact have not been independently cleared.
- Original label provenance, collection timestamps and campaign identities are unavailable.
- A source-held-out and time-held-out evaluation has not been performed.
- The deployed feature extractor and training extractor must stay schema-identical; tests enforce the ordered feature list.

Treat this model as an experimental aid only. Do not use it to automatically block or allow messages, or to claim a safe/legitimate result.
