# In plain English: these tests check the "meaning numbers" side of the
# service. They load the real AI model, so the first run downloads it (about
# 130 MB) unless it is already saved on the machine. No database is needed.
from app.embeddings import embed_text
from app.examples import _vector_text


# In plain English: a quick score of how alike two lists of numbers are
# (cosine similarity). 1 means pointing the same way, near 0 means unrelated.
def similarity(a, b):
    dot = sum(x * y for x, y in zip(a, b))
    size_a = sum(x * x for x in a) ** 0.5
    size_b = sum(y * y for y in b) ** 0.5
    return dot / (size_a * size_b)


# In plain English: the numbers must be written the way the database expects,
# like "[0.1,0.2,0.3]" with no spaces.
def test_vector_text_format():
    assert _vector_text([0.1, 0.2, 0.3]) == "[0.1,0.2,0.3]"


# In plain English: every text must become exactly 384 numbers, because that is
# the size of the database column. Any other size would be refused on save.
def test_embedding_has_384_numbers():
    numbers = embed_text("hello world")
    assert len(numbers) == 384
    assert all(isinstance(number, float) for number in numbers)


# In plain English: the point of the whole service. A question about cells and
# energy must land closer to the mitochondria sentence than to the sunlight one.
def test_similar_meaning_scores_higher():
    query = embed_text("cells produce energy")
    close = embed_text("The mitochondria makes energy for the cell.")
    far = embed_text("Plants make food from sunlight.")
    assert similarity(query, close) > similarity(query, far)
