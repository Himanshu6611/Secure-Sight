# Local image corpus audit

Audit scope: folder names and split counts only, plus one JPEG header sample from Dataset 1. No image files were opened for visual review and no training was run.

| Folder | Train fake / real | Validation fake / real | Test fake / real |
|---|---:|---:|---:|
| Data Set 1 | 20,001 / 20,001 | 6,161 / 6,199 | 2,623 / 2,604 |
| Data Set 2 | 20,000 / 20,000 | 6,160 / 6,196 | 2,623 / 2,603 |
| Data Set 3 | 20,000 / 20,000 | 6,160 / 6,196 | 2,623 / 2,603 |
| Data Set 4 | 16,051 / 20,000 | 6,160 / 6,196 | unavailable |

The directory labels say only `fake` and `real`. The workspace has no source manifest, exact dataset identity, license, generator labels, capture provenance, subject identity, or duplicate/near-duplicate report for these folders. Dataset 4 has no test split. Similar split counts do not establish that the folders are independent. These images are therefore not approved for production training, training-set claims, or accuracy claims.

The previously recorded HOG plus color-histogram experiment used a sample from Data Set 1 and failed its quality gate (test accuracy 73.8%; false-positive rate 36.8%). It is a rejected research baseline, not the deployed image detector. No validated general-purpose synthetic-image or deepfake model is installed.

SecureSight can report generator information only when an image contains a supported Content Credentials record that names it. That is a signed manifest declaration; trusted-signature status and the claim's truth are kept separate. SynthID checks a supported watermark family through Google's own detector. SecureSight does not submit uploaded images to that service. Without either form of usable evidence, the correct result is **origin unknown**, not “real” or “AI-generated.”

To approve a future model, first recover the original dataset sources and license terms; identify generation methods and genuine-image sources; detect exact and perceptual duplicates across all splits; then create source-, subject-, and time-disjoint holdouts. Report per-source precision/recall, false-positive rates, calibration and confidence intervals before considering deployment.
