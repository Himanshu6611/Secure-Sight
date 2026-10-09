# Safe static web retrieval

utils/safe_fetch.py uses app/security/outbound.py pinned_pool, not a requests transport. DNS resolution uses bounded lifetimes and rejects any restricted answer. HTTP connects to a validated literal; HTTPS preserves Host, SNI and hostname verification. There is no implicit proxy, retry or redirect handling.

Each of up to three redirects revalidates URL/DNS/address policy. Total default deadline is six seconds, body cap 1 MiB. Only successful HTML/XHTML responses with identity encoding are accepted. Every response and pool closes on success/failure. Failure statuses are explicit and safe; failed HTML is not converted into benign zero features.

Static DOM checks enforce byte/node/depth/resource budgets. JavaScript/forms do not execute. Infrastructure egress restrictions remain required for public deployment.
