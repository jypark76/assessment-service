# In plain English: this file turns a piece of text into a list of 384 numbers
# that capture its meaning. Two texts that mean similar things get similar
# numbers, which is how the service will later find "similar examples". The AI
# model runs inside this box. Nothing is sent to any outside company.
import os
import threading

from fastembed import TextEmbedding

# The small, free model we chose. It produces 384 numbers per text, which is
# exactly the size of the "embedding" column in the database.
MODEL_NAME = "BAAI/bge-small-en-v1.5"

# Holds the model once it is loaded, so we only pay the loading cost one time.
_model = None

# A turnstile for loading the model. Without it, two requests that arrive at the
# very same moment on a cold start could both load the model and briefly use
# double the memory.
_load_lock = threading.Lock()


# In plain English: gives back the model, loading it from disk the first time
# it is needed and reusing it after that. The model files are saved into the
# image when it is built (see the Dockerfile), so no download happens here. If
# several requests ask at the same moment, only the first one loads it. The
# others wait at the turnstile and then reuse it. The second check inside the
# turnstile is what stops the late arrivals from loading it again.
def _get_model():
    global _model
    if _model is None:
        with _load_lock:
            if _model is None:
                _model = TextEmbedding(
                    model_name=MODEL_NAME,
                    cache_dir=os.environ.get("FASTEMBED_CACHE_PATH"),
                )
    return _model


# In plain English: takes some text and returns its 384 numbers as a plain
# Python list of decimals, ready to be saved in or compared against the
# database.
def embed_text(text):
    vectors = list(_get_model().embed([text]))
    return [float(number) for number in vectors[0]]
