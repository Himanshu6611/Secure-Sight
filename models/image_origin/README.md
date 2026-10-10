# SecureSight experimental AI-image-pattern model

This is a compact CNN trained from scratch and run locally with ONNX Runtime;
image inference sends no image to a third-party API. It estimates whether a
96×96 image resembles the AI-generated class in the training source. It does
not prove an image is real or fake, identify its generator, detect face swaps,
or establish that a person or scene is authentic. The sigmoid score is
uncalibrated and must not be described as a correctness probability.

## Data and evaluation

Training used all 79,950 labeled rows from the AI vs Human Generated Dataset:
authentic Shutterstock images and AI-generated counterparts. The provider
declares Apache 2.0 terms; the Hugging Face mirror itself has no license field,
so review upstream terms and preserve attribution before commercial use. The
mirror's separate 5,540-row test split returned label `-1`, so it was not used
for accuracy claims.

The labeled training rows were divided by adjacent counterpart pair into
55,962 fit examples, 11,994 validation examples, and 11,994 held-out test
examples. No pair crossed a split. The validation split selected threshold
`0.6579` to target a false-positive rate no higher than 5%.

On that held-out split, the new model achieved 94.4% balanced accuracy, 4.9%
false positives, and 6.3% false negatives (95% pair-bootstrap interval for
balanced accuracy: 94.0–94.8%). The prior model scored 87.8% balanced accuracy,
4.6% false positives, and 19.8% false negatives on the same images. After
JPEG quality-82 recompression, the new model scored 93.2% balanced accuracy,
3.1% false positives, and 10.5% false negatives; the prior model scored 83.4%,
3.1%, and 30.1%, respectively. PyTorch-to-ONNX maximum logit difference on
128 held-out images was `0.0000067`.

These results measure a pair-grouped holdout from the same labeled dataset
family, not independent current generators, social-media reposts, screenshots,
edited photos, or deepfakes. Independent external validation is still needed.
The application therefore presents an experimental AI-pattern estimate, not
a definitive `Real` / `Fake` or safe / unsafe verdict.

Dataset and declared terms: [provider page](https://www.innovatiana.com/en/datasets/ai-vs-human-generated-dataset). The mirror's row counts and files are at [Hugging Face](https://huggingface.co/datasets/Ransaka/ai-vs-human-generated-dataset).

See [local retraining instructions](../../docs/MEDIA_MODEL_TRAINING.md) for the
training command, split checks, model comparison, and ONNX parity test.
