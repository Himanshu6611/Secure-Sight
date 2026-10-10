# Training the local image-origin model

SecureSight's image-origin estimate is a compact CNN trained from scratch and
run locally through ONNX Runtime. Image inference makes no third-party API
request. It estimates resemblance to a dataset's AI-generated class; it does
not determine whether a person is a deepfake, whether a photo is authentic, or
which model generated an image.

## Data and rights

The **AI vs Human Generated Dataset** provider describes authentic Shutterstock
images paired with AI-generated counterparts and declares Apache 2.0 terms.
The Hugging Face mirror reports 79,950 labeled training rows and 5,540 test
rows. Its separate test split currently returns `label = -1` through the
dataset viewer, so it cannot serve as labeled test evidence. Training therefore
uses pair-grouped fit, validation, and test splits from labeled training rows;
the evaluation report records this limitation. The mirror's card does not
itself specify a license, so review the provider's terms and preserve
attribution before commercial use. Do not use the unlicensed local `Data Set`
folders for training.

Provider/license information: <https://www.innovatiana.com/en/datasets/ai-vs-human-generated-dataset>

Dataset mirror and split details: <https://huggingface.co/datasets/Ransaka/ai-vs-human-generated-dataset>

## Reproducible local training

Install training-only dependencies:

```powershell
python -m pip install -r requirements-image-train.txt
```

Download the labeled training files to a local data directory. The split is
about 4.6 GB; do not commit it:

```powershell
huggingface-cli download Ransaka/ai-vs-human-generated-dataset `
  --repo-type dataset `
  --include "data/train-*.parquet" `
  --local-dir D:\SecureSight-image-dataset
```

Train to a candidate directory first. The script writes resized pixel caches
outside the repository, groups adjacent real/AI counterparts into fit,
validation, and test sets, compares the candidate with the current ONNX model
on the same held-out images, and checks ONNX output against PyTorch:

```powershell
python scripts/train_image_origin_model.py `
  --train-dir D:\SecureSight-image-dataset\data `
  --cache-dir D:\SecureSight-image-cache `
  --output D:\SecureSight-image-candidate
```

The output `evaluation.json` records source shard hashes, data coverage,
pair-split checks, the validation-selected threshold, held-out metrics, JPEG
recompression metrics, baseline comparison, and ONNX parity. Keep a candidate
out of production if it does not improve on the existing model or has
unacceptable false-positive / false-negative rates. The score is uncalibrated;
never present it as a probability or definitive real/fake verdict.
