# Content Credentials

The installed `c2pa-python==0.38.0` SDK reads original bytes. Integrity and trust validation run with remote-manifest and OCSP fetch disabled. States: VALID for SDK Trusted; PRESENT_UNVERIFIED for signed Valid without trusted anchors; INVALID for Invalid; ABSENT for missing credentials; UNSUPPORTED when SDK is unavailable; ERROR for parsing/configuration failure. Signature validity and trust are separate fields.

Optional `C2PA_TRUST_ANCHORS_FILE` is an operator-provisioned PEM file, bounded to 64 KiB. Uploads cannot provide anchors. No uploaded certificate is automatically trusted. Revocation retrieval is disabled and reported as NOT_FETCHED_OFFLINE; this limits any trust conclusion. No manifest authors, identities or raw assertions are returned.

Tests create an ephemeral certificate chain and actual signed image, verify a trusted signature with test-only anchors, distinguish untrusted signatures, and detect tampered image bytes. Missing credentials never prove fabrication. Valid credentials do not prove truthful depicted content.

Primary SDK reference: [official context settings](https://github.com/contentauth/c2pa-python/blob/main/docs/context-settings.md).
