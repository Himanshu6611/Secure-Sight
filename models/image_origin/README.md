# Experimental AI-generated-image pattern model

This small CPU inference model is trained from scratch on the **AI vs Human Generated Dataset**. The provider describes 85,500 images, authentic Shutterstock photographs paired with AI-generated equivalents, and an Apache 2.0 commercial-use license. Dataset attribution and terms: [Innovatiana dataset page](https://www.innovatiana.com/en/datasets/ai-vs-human-generated-dataset). Upstream archive: [Kaggle dataset](https://www.kaggle.com/datasets/alessandrasala79/ai-vs-human-generated-dataset). The local training run used only the recorded shard and never includes source images in this repository.

## Scope and result

The model estimates whether a 96×96 image has patterns resembling the dataset's AI-generated class. It is **not** a deepfake, face-swap, image-editing, ownership, identity, or truth detector. Its sigmoid output is an uncalibrated model score, not a probability that the image is AI-made. A score below the decision threshold means only that the model did not flag the pattern.

The split kept adjacent equivalent real/AI examples together. Training used 4,795 images, threshold selection used a separate 1,600-image validation set, and the final 1,600-image test set was not used for fitting or threshold selection. On that one-dataset, one-shard test set, the validation-selected 0.7093 threshold produced 87.6% balanced accuracy, 4.1% false positives, and 20.8% false negatives. Re-encoding test images as JPEG quality 82 yielded 87.0% balanced accuracy, 4.0% false positives, and 22.0% false negatives. At threshold 0.5, test balanced accuracy was 89.6%, false positives 8.5%, and false negatives 12.4%.

These are internal dataset results, not independent real-world validation. No results are available for current generators outside this dataset, social-media transformations, screenshots, edited real images, or face deepfakes. Do not present the model's result as a definitive “real” or “fake” verdict. The app labels it an experimental AI-pattern estimate and keeps its general image-authenticity/threat verdict separate.
