# OCR intelligence

Tesseract performs actual sparse-text recognition (`--psm 11`) with a four-second subprocess timeout. Up to 256 words contain real OCR word confidence, bounding boxes, language and original SHA256. Confidence is Tesseract's output, not validated correctness probability. Text is bounded to 8192 characters and never interpreted as code. HTML rendering uses Jinja escaping; API consumers must render text as text.

HTTP(S) text destinations are passed to the existing website scanner, sharing the one-destination cap with QR. Registry names provide textual brand observations; they are not visual logo recognition. Bounded regex observations identify email, phone, amount and date spans, returning hashes instead of entity values; credential terms are contextual and unscored. These patterns are not validated semantic classifiers. Returned text can contain private content supplied by the caller: never log it or persist the response without an explicit retention policy. No OCR text is logged by this implementation.

Real English and Hindi/English fixtures are tested locally. Recognition quality varies with layout and image quality. Detailed phone/email/amount/date entity extraction and sensitive-span masking are not implemented; callers must treat the response as private.
