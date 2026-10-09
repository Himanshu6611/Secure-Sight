# Dataset card: frozen URL corpus 5.1.1

Source: [UCI PhiUSIIL](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset), donated 3 March 2024, CC BY 4.0, Arvind Prasad and Shalini Chandra. Preserve attribution for redistribution. Original labels 1=legitimate/0=phishing are converted to project 0=legitimate/1=phishing. Local retrieval date was not recorded; it cannot be reconstructed from training time.

235,795 publisher rows; 234,885 cleaned rows (134,849 legitimate, 100,036 phishing). 910 duplicate removals/merges; one conflicting normalized URL resolved by majority, tie to phishing. This label resolution can introduce bias; labels are publisher labels, not independent contemporary adjudication. URL normalization/IDNA and SHA256 URL+label identity are checked. Publisher filename/similarity/target-derived fields are excluded: 59 lexical URL features observed; remaining 38 schema slots are explicitly NaN. URL query/path text can contain PII or tokens; corpus remains local, no raw URLs/emails in public report, no production captures in fixtures. External corpus redistribution requires review of sensitive URLs beyond license compliance.

| Partition | Rows | Registrable domains | Legitimate | Phishing |
|---|---:|---:|---:|---:|
| train | 165436 | 137231 | 94360 | 71076 |
| calibration | 16858 | 14703 | 10128 | 6730 |
| threshold_selection | 17037 | 14704 | 10190 | 6847 |
| test | 35554 | 29407 | 20171 | 15383 |

Frozen grouped partitions have zero domain, row and normalized near-URL cross-partition overlap. Near-URL check decodes path/sorts query/removes scheme/fragment; it is not semantic page/image duplicate detection. All actual domains and row identifiers recomputed, source/features/rows/split/model checksums verified; train medians and grouped OOF separation verified. Sigmoid calibration uses calibration rows; operating threshold uses threshold-selection rows. Campaign IDs, capture dates and raw page/image clones are absent: campaign/temporal leakage and future external performance remain UNAVAILABLE. Offline static PSL avoids network-dependent grouping. Geography, language, capture-era and publisher selection biases limit representativeness. Previously inspected holdout is historical replay, not a new unseen test set.

Source SHA256: `a236549cd369cd80bd478ff8e1779cbf44c58d5c3f79f7a51a1adbed7d06d1c6`; split SHA256: `ad354fcd3ec995f63b6c099a73861216c1cc3cb2580f0bc889be1714399bf843`.
