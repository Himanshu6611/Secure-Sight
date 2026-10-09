"""Bounded name similarity; outputs are context, never verdicts."""
import unicodedata

# Deliberately limited common Cyrillic/Greek confusables; not a complete TR39 implementation.
CONFUSABLES = str.maketrans({"а":"a", "е":"e", "о":"o", "р":"p", "с":"c", "у":"y", "х":"x",
    "і":"i", "ј":"j", "ѕ":"s", "ο":"o", "ρ":"p", "α":"a", "ν":"v", "ι":"i"})


def skeleton(value):
    return unicodedata.normalize("NFKC", value).casefold().translate(CONFUSABLES)


def levenshtein(a, b):
    if len(a) > 253 or len(b) > 253:
        raise ValueError("Similarity input limit")
    previous = list(range(len(b) + 1))
    for i, left in enumerate(a, 1):
        current = [i]
        for j, right in enumerate(b, 1):
            current.append(min(current[-1] + 1, previous[j] + 1, previous[j-1] + (left != right)))
        previous = current
    return previous[-1]


def jaro_winkler(a, b):
    if len(a) > 253 or len(b) > 253:
        raise ValueError("Similarity input limit")
    if a == b:
        return 1.0
    if not a or not b:
        return 0.0
    window = max(0, max(len(a), len(b)) // 2 - 1)
    left, right = [False] * len(a), [False] * len(b)
    for i, char in enumerate(a):
        for j in range(max(0, i-window), min(len(b), i+window+1)):
            if not right[j] and char == b[j]:
                left[i] = right[j] = True
                break
    matches = sum(left)
    if not matches:
        return 0.0
    ordered_a = [c for c, match in zip(a, left) if match]
    ordered_b = [c for c, match in zip(b, right) if match]
    transpositions = sum(x != y for x, y in zip(ordered_a, ordered_b)) / 2
    score = (matches/len(a) + matches/len(b) + (matches-transpositions)/matches) / 3
    prefix = 0
    for x, y in zip(a[:4], b[:4]):
        if x != y:
            break
        prefix += 1
    return score + prefix * .1 * (1-score) if score > .7 else score


def compare(label, reference):
    distance = levenshtein(label, reference)
    patterns = []
    if label != reference:
        if distance == 1:
            patterns.append("INSERTION" if len(label) > len(reference) else "DELETION" if len(label) < len(reference) else "SUBSTITUTION")
        if len(label) == len(reference) and any(label == reference[:i] + reference[i+1] + reference[i] + reference[i+2:] for i in range(len(reference)-1)):
            patterns.append("TRANSPOSITION")
        if label.replace("-", "") == reference:
            patterns.append("HYPHENATION")
        if "".join(c for c in label if not c.isdigit()) == reference:
            patterns.append("NUMBER_INSERTION")
        if reference in label:
            patterns.append("BRAND_TOKEN_PREFIX_SUFFIX")
    return dict(levenshtein=distance, jaro_winkler=round(jaro_winkler(label, reference), 4), patterns=patterns)
