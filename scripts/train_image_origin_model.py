"""Train SecureSight's small, local AI-image-pattern model.

The script expects the Apache-2.0-provider-declared AI vs Human Generated
Dataset mirror's labeled train parquet files. Its separate mirror test split
has missing labels, so the script reserves pair-disjoint validation and test
groups from the labeled train split. It then exports an ONNX artifact for local
CPU inference. This is not a deepfake detector.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from io import BytesIO
from pathlib import Path

import numpy as np
import pyarrow.parquet as pq
import torch
from PIL import Image, ImageOps
from sklearn.metrics import (accuracy_score, balanced_accuracy_score,
                             confusion_matrix, precision_score, recall_score,
                             roc_auc_score)
from sklearn.model_selection import GroupShuffleSplit
from torch import nn
from torch.utils.data import DataLoader, Dataset


class CompactCNN(nn.Module):
    """Compact five-stage CNN, trained from scratch and used for CPU ONNX."""

    def __init__(self):
        super().__init__()
        layers = []
        channels = (3, 16, 24, 32, 48, 64)
        for source, target in zip(channels, channels[1:]):
            layers.extend((nn.Conv2d(source, target, 3, stride=2, padding=1, bias=False),
                           nn.BatchNorm2d(target), nn.ReLU(inplace=True)))
        self.features = nn.Sequential(*layers)
        self.head = nn.Sequential(nn.AdaptiveAvgPool2d(1), nn.Flatten(), nn.Linear(64, 1))

    def forward(self, x):
        return self.head(self.features(x)).squeeze(1)


def parquet_files(directory: Path, split: str) -> list[Path]:
    files = sorted(directory.glob(f"{split}-*.parquet"))
    if not files:
        raise FileNotFoundError(f"No {split}-*.parquet files found in {directory}")
    return files


def prepare_memmap(files: list[Path], cache_dir: Path, split: str):
    """Stream parquet row groups into a fixed-size uint8 image memmap.

    This bounds memory use while decoding the 11 GB source archive. The cache
    contains only resized training examples and lives outside the git tree.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    image_path = cache_dir / f"{split}-96x96-rgb.npy"
    labels_path = cache_dir / f"{split}-labels.npy"
    manifest_path = cache_dir / f"{split}-manifest.json"
    source = [{"name": path.name, "bytes": path.stat().st_size} for path in files]
    expected_rows = sum(pq.ParquetFile(path).metadata.num_rows for path in files)
    expected_manifest = {"source": source, "rows": expected_rows, "size": 96}
    if image_path.exists() and labels_path.exists() and manifest_path.exists():
        if json.loads(manifest_path.read_text(encoding="utf-8")) == expected_manifest:
            return np.load(image_path, mmap_mode="r"), np.load(labels_path), expected_rows

    images = np.lib.format.open_memmap(image_path, mode="w+", dtype=np.uint8,
                                      shape=(expected_rows, 96, 96, 3))
    labels = np.lib.format.open_memmap(labels_path, mode="w+", dtype=np.uint8,
                                      shape=(expected_rows,))
    cursor = 0
    for path in files:
        parquet = pq.ParquetFile(path)
        print(f"preparing {split}: {path.name} rows={parquet.metadata.num_rows}", flush=True)
        for row_group in range(parquet.num_row_groups):
            table = parquet.read_row_group(row_group, columns=["image", "label"])
            byte_values = table.column("image").combine_chunks().field("bytes").to_pylist()
            row_labels = table.column("label").to_pylist()
            for raw, label in zip(byte_values, row_labels, strict=True):
                label = int(label)
                if label not in (0, 1) or not raw:
                    raise ValueError(f"Unexpected image or label in {path.name} row {cursor}")
                with Image.open(BytesIO(raw)) as source_image:
                    image = ImageOps.fit(ImageOps.exif_transpose(source_image).convert("RGB"),
                                         (96, 96), method=Image.Resampling.BICUBIC,
                                         centering=(0.5, 0.5))
                    images[cursor] = np.asarray(image, dtype=np.uint8)
                labels[cursor] = label
                cursor += 1
            del table, byte_values, row_labels
            images.flush()
            labels.flush()
            print(f"prepared {split}: {cursor}/{expected_rows}", flush=True)
    if cursor != expected_rows:
        raise ValueError(f"Read {cursor} rows, expected {expected_rows}")
    del images, labels
    np.save(labels_path.with_suffix(".tmp.npy"), np.load(labels_path, mmap_mode="r"))
    labels_path.with_suffix(".tmp.npy").replace(labels_path)
    manifest_path.write_text(json.dumps(expected_manifest, indent=2) + "\n", encoding="utf-8")
    return np.load(image_path, mmap_mode="r"), np.load(labels_path), expected_rows


class ImageRows(Dataset):
    def __init__(self, images, labels, indices, augment=False, jpeg_quality=None):
        self.images, self.labels = images, labels
        self.indices = np.asarray(indices, dtype=np.int64)
        self.augment, self.jpeg_quality = augment, jpeg_quality

    def __len__(self):
        return len(self.indices)

    def __getitem__(self, position):
        index = int(self.indices[position])
        array = np.asarray(self.images[index]).copy()
        if self.jpeg_quality is not None:
            buffer = BytesIO()
            Image.fromarray(array).save(buffer, format="JPEG", quality=self.jpeg_quality)
            buffer.seek(0)
            with Image.open(buffer) as compressed:
                array = np.asarray(compressed.convert("RGB"), dtype=np.uint8).copy()
        tensor = torch.from_numpy(array).permute(2, 0, 1).float().div_(255.0)
        if self.augment:
            if torch.rand(()) < 0.5:
                tensor = tensor.flip(-1)
            # Mild variation makes the classifier less dependent on exact
            # color and compression signatures while preserving image content.
            brightness = float(torch.empty(()).uniform_(0.88, 1.12))
            contrast = float(torch.empty(()).uniform_(0.90, 1.10))
            mean = tensor.mean(dim=(1, 2), keepdim=True)
            tensor = ((tensor - mean) * contrast + mean) * brightness
            tensor.clamp_(0.0, 1.0)
        return tensor, torch.tensor(float(self.labels[index]))


def predict(model, images, labels, indices, batch_size, jpeg_quality=None):
    loader = DataLoader(ImageRows(images, labels, indices, jpeg_quality=jpeg_quality),
                        batch_size=batch_size, shuffle=False, num_workers=0)
    scores, truth = [], []
    model.eval()
    with torch.inference_mode():
        for x, y in loader:
            scores.extend(torch.sigmoid(model(x)).numpy().tolist())
            truth.extend(y.numpy().astype(int).tolist())
    return np.asarray(truth), np.asarray(scores)


def predict_onnx(path, images, labels, indices, batch_size, jpeg_quality=None):
    import onnxruntime as ort
    session = ort.InferenceSession(str(path), providers=["CPUExecutionProvider"])
    input_batch = session.get_inputs()[0].shape[0]
    effective_batch = 1 if input_batch == 1 else batch_size
    loader = DataLoader(ImageRows(images, labels, indices, jpeg_quality=jpeg_quality),
                        batch_size=effective_batch, shuffle=False, num_workers=0)
    scores, truth = [], []
    with torch.inference_mode():
        for x, y in loader:
            logits = session.run(["logit"], {"image": x.numpy()})[0]
            scores.extend((1.0 / (1.0 + np.exp(-np.clip(logits, -80, 80)))).tolist())
            truth.extend(y.numpy().astype(int).tolist())
    return np.asarray(truth), np.asarray(scores)


def summarize(actual, scores, threshold):
    predicted = (scores >= threshold).astype(int)
    matrix = confusion_matrix(actual, predicted, labels=[0, 1]).tolist()
    tn, fp, fn, tp = np.asarray(matrix).ravel().tolist()
    return {
        "accuracy": float(accuracy_score(actual, predicted)),
        "balanced_accuracy": float(balanced_accuracy_score(actual, predicted)),
        "roc_auc": float(roc_auc_score(actual, scores)),
        "precision_ai": float(precision_score(actual, predicted, zero_division=0)),
        "recall_ai": float(recall_score(actual, predicted, zero_division=0)),
        "false_positive_rate": fp / (fp + tn) if fp + tn else None,
        "false_negative_rate": fn / (fn + tp) if fn + tp else None,
        "confusion_matrix_labels_0_authentic_1_ai": matrix,
    }


def pair_bootstrap_balanced_accuracy_ci(actual, scores, threshold, seed):
    """95% interval resampling each adjacent real/AI pair as one unit."""
    if len(actual) < 4 or len(actual) % 2:
        return None
    pairs = np.arange(len(actual) // 2)
    pair_truth = actual.reshape(-1, 2)
    if not np.all(pair_truth[:, 0] != pair_truth[:, 1]):
        return None
    predicted = scores >= threshold
    rng = np.random.default_rng(seed)
    estimates = np.empty(1000, dtype=np.float32)
    for iteration in range(len(estimates)):
        sampled = rng.choice(pairs, size=len(pairs), replace=True)
        rows = np.column_stack((sampled * 2, sampled * 2 + 1)).reshape(-1)
        truth, guess = actual[rows], predicted[rows]
        tpr = np.mean(guess[truth == 1])
        tnr = np.mean(~guess[truth == 0])
        estimates[iteration] = (tpr + tnr) / 2
    low, high = np.quantile(estimates, [0.025, 0.975])
    return [float(low), float(high)]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--train-dir", required=True, type=Path,
                        help="Directory containing the source train-*.parquet files")
    parser.add_argument("--cache-dir", required=True, type=Path,
                        help="External scratch path for resized memmap caches")
    parser.add_argument("--output", type=Path, default=Path("models/image_origin_candidate"))
    parser.add_argument("--epochs", type=int, default=5)
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--threads", type=int, default=4)
    args = parser.parse_args()
    if args.epochs < 1 or args.batch_size < 1 or args.threads < 1:
        parser.error("epochs, batch-size, and threads must be positive")
    torch.manual_seed(20261010)
    np.random.seed(20261010)
    torch.set_num_threads(args.threads)

    train_files = parquet_files(args.train_dir, "train")
    def shard_coverage(files, split):
        match = re.search(rf"{split}-\d+-of-(\d+)\.parquet$", files[0].name)
        expected_shards = int(match.group(1)) if match else None
        return {"downloaded_shards": len(files), "expected_shards": expected_shards,
                "complete": expected_shards == len(files) if expected_shards else None}
    train_coverage = shard_coverage(train_files, "train")
    if train_coverage["complete"] is False:
        raise ValueError(f"Incomplete training split: {train_coverage}")
    train_images, train_labels, train_count = prepare_memmap(
        train_files, args.cache_dir, "train")
    if train_count % 2:
        raise ValueError("Source split has an incomplete adjacent image pair")
    if not np.all(train_labels[::2] != train_labels[1::2]):
        raise ValueError("Labeled rows do not match the documented adjacent-pair ordering")

    train_indices = np.arange(train_count)
    pair_groups = train_indices // 2
    holdout_split = GroupShuffleSplit(n_splits=1, test_size=0.15, random_state=20261010)
    fit_valid_idx, test_idx = next(holdout_split.split(train_indices, train_labels, pair_groups))
    validation_split = GroupShuffleSplit(n_splits=1, test_size=0.17647058823529413,
                                         random_state=20261011)
    fit_rel, valid_rel = next(validation_split.split(
        fit_valid_idx, train_labels[fit_valid_idx], pair_groups[fit_valid_idx]))
    fit_idx, valid_idx = fit_valid_idx[fit_rel], fit_valid_idx[valid_rel]
    model = CompactCNN()
    optimizer = torch.optim.AdamW(model.parameters(), lr=0.001, weight_decay=0.0005)
    loss_fn = nn.BCEWithLogitsLoss()
    train_loader = DataLoader(ImageRows(train_images, train_labels, fit_idx, augment=True),
                              batch_size=args.batch_size, shuffle=True, num_workers=0)
    valid_loader = DataLoader(ImageRows(train_images, train_labels, valid_idx),
                              batch_size=args.batch_size, shuffle=False, num_workers=0)
    best_loss, best_state, stale_epochs = float("inf"), None, 0
    history = []
    for epoch in range(args.epochs):
        model.train()
        losses = []
        for x, y in train_loader:
            optimizer.zero_grad(set_to_none=True)
            loss = loss_fn(model(x), y)
            loss.backward()
            optimizer.step()
            losses.append(float(loss.item()))
        model.eval()
        val_losses = []
        with torch.inference_mode():
            for x, y in valid_loader:
                val_losses.append(float(loss_fn(model(x), y).item()))
        train_loss, val_loss = float(np.mean(losses)), float(np.mean(val_losses))
        history.append({"epoch": epoch + 1, "train_loss": train_loss, "validation_loss": val_loss})
        print(f"epoch={epoch + 1} train_loss={train_loss:.4f} validation_loss={val_loss:.4f}",
              flush=True)
        if val_loss < best_loss:
            best_loss = val_loss
            best_state = {key: value.detach().clone() for key, value in model.state_dict().items()}
            stale_epochs = 0
        else:
            stale_epochs += 1
            if stale_epochs >= 2:
                print("early stopping after validation loss stopped improving", flush=True)
                break
    if best_state is None:
        raise RuntimeError("Training did not produce a valid checkpoint")
    model.load_state_dict(best_state)

    valid_truth, valid_scores = predict(model, train_images, train_labels, valid_idx,
                                        args.batch_size)
    negative_scores = valid_scores[valid_truth == 0]
    threshold = float(np.quantile(negative_scores, 0.95, method="higher"))
    test_truth, test_scores = predict(model, train_images, train_labels, test_idx,
                                      args.batch_size)
    jpeg_truth, jpeg_scores = predict(model, train_images, train_labels, test_idx,
                                      args.batch_size, jpeg_quality=82)
    baseline_path = Path(__file__).resolve().parents[1] / "models" / "image_origin" / "image_origin_cnn.onnx"
    baseline_metrics = None
    if baseline_path.exists():
        baseline_truth, baseline_scores = predict_onnx(
            baseline_path, train_images, train_labels, test_idx, args.batch_size)
        baseline_jpeg_truth, baseline_jpeg_scores = predict_onnx(
            baseline_path, train_images, train_labels, test_idx, args.batch_size, jpeg_quality=82)
        baseline_eval_path = baseline_path.with_name("evaluation.json")
        baseline_eval = json.loads(baseline_eval_path.read_text(encoding="utf-8"))
        baseline_threshold = float(baseline_eval["decision_threshold"])
        baseline_metrics = {
            "model_sha256": sha256(baseline_path),
            "threshold": baseline_threshold,
            "test_at_existing_threshold": summarize(baseline_truth, baseline_scores, baseline_threshold),
            "test_at_0_5": summarize(baseline_truth, baseline_scores, 0.5),
            "jpeg_test_at_existing_threshold_quality_82": summarize(
                baseline_jpeg_truth, baseline_jpeg_scores, baseline_threshold),
            "balanced_accuracy_95pct_pair_bootstrap_ci": pair_bootstrap_balanced_accuracy_ci(
                baseline_truth, baseline_scores, baseline_threshold, 20261012),
        }

    args.output.mkdir(parents=True, exist_ok=True)
    onnx_path = args.output / "image_origin_cnn.onnx"
    torch.onnx.export(model, torch.zeros(1, 3, 96, 96), str(onnx_path),
                      input_names=["image"], output_names=["logit"],
                      dynamic_axes={"image": {0: "batch"}, "logit": {0: "batch"}},
                      opset_version=17, dynamo=False)
    import onnxruntime as ort
    session = ort.InferenceSession(str(onnx_path), providers=["CPUExecutionProvider"])
    probe = np.asarray(train_images[test_idx[:min(128, len(test_idx))]], dtype=np.float32)
    probe = np.transpose(probe / 255.0, (0, 3, 1, 2)).copy()
    with torch.inference_mode():
        torch_probe = model(torch.from_numpy(probe)).numpy()
    onnx_probe = session.run(["logit"], {"image": probe})[0]
    max_delta = float(np.max(np.abs(torch_probe - onnx_probe)))
    if max_delta > 1e-4:
        raise RuntimeError(f"PyTorch/ONNX mismatch: {max_delta}")

    source_info = {
        "name": "AI vs Human Generated Dataset",
        "source": "Kaggle/alessandrasala79; mirror by Ransaka on Hugging Face",
        "license": "Apache-2.0 as declared by the dataset provider; verify source terms before commercial use",
        "license_source": "https://www.innovatiana.com/en/datasets/ai-vs-human-generated-dataset",
        "upstream": "https://huggingface.co/datasets/Ransaka/ai-vs-human-generated-dataset",
        "labels": {"0": "authentic Shutterstock image", "1": "AI-generated counterpart"},
        "pairing_check": "Adjacent rows have opposite labels; pair groups never cross fit/validation/test splits",
        "train_files": [{"name": p.name, "bytes": p.stat().st_size, "sha256": sha256(p)}
                        for p in train_files],
        "labeled_train_file_count": len(train_files),
    }
    metrics = {
        "dataset": source_info,
        "architecture": "Compact 5-stage CNN, 96x96 RGB, trained from scratch",
        "training_split": "70% of labeled source train rows; pair-grouped validation/test splits; best validation loss checkpoint",
        "test_split": "Pair-grouped 15% holdout from the labeled source training split; the mirror's separate test split is unlabeled",
        "train_examples": int(len(fit_idx)), "validation_examples": int(len(valid_idx)),
        "test_examples": int(len(test_idx)),
        "download_coverage": {"labeled_train": train_coverage},
        "pair_groups_disjoint": not bool(
            (set(pair_groups[fit_idx]) & set(pair_groups[valid_idx])) or
            (set(pair_groups[fit_idx]) & set(pair_groups[test_idx])) or
            (set(pair_groups[valid_idx]) & set(pair_groups[test_idx]))),
        "validation_target_fpr": 0.05,
        "validation_threshold": threshold,
        "test_at_selected_threshold": summarize(test_truth, test_scores, threshold),
        "test_at_default_0_5": summarize(test_truth, test_scores, 0.5),
        "jpeg_reencoded_test_at_selected_threshold_quality_82": summarize(jpeg_truth, jpeg_scores, threshold),
        "balanced_accuracy_95pct_pair_bootstrap_ci": pair_bootstrap_balanced_accuracy_ci(
            test_truth, test_scores, threshold, 20261011),
        "jpeg_balanced_accuracy_95pct_pair_bootstrap_ci": pair_bootstrap_balanced_accuracy_ci(
            jpeg_truth, jpeg_scores, threshold, 20261013),
        "existing_model_on_same_pair_grouped_holdout": baseline_metrics,
        "training_history": history,
        "onnx_max_abs_logit_delta_vs_pytorch_128_test_images": max_delta,
        "score_is_calibrated_probability": False,
        "limitations": [
            "The score is not a calibrated probability or proof of image origin.",
            "The source dataset covers paired Shutterstock photos and AI counterparts, not face swaps or deepfakes.",
            "The mirror's separate test split is unlabeled; this held-out test shares the labeled training source family.",
            "Independent current-generator and social-media validation is still required.",
        ],
    }
    metrics["model_sha256"] = sha256(onnx_path)
    metrics["decision_threshold"] = threshold
    (args.output / "evaluation.json").write_text(json.dumps(metrics, indent=2) + "\n",
                                                  encoding="utf-8")
    print(json.dumps(metrics, indent=2), flush=True)


if __name__ == "__main__":
    main()
