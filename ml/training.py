"""Supported training entry point. Legacy zero-filled training is retired."""
from ml.corrected_training import main, generate_dataset
from ml.dataset import split_dataset_by_domain_group


def load_and_prepare_dataset():
    rows, features, manifest = generate_dataset()
    return rows, features, manifest


if __name__ == "__main__":
    main()
