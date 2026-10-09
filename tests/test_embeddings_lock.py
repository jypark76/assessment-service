# In plain English: the embedding model is big, so it must be loaded only once.
# If two requests arrive at the very same moment on a cold start, both could try
# to load it and briefly use double the memory, which risks the memory limit. This
# test uses a slow pretend model so the race is easy to trigger, asks for the
# model from 8 threads at once, and checks that it was loaded exactly once.
import threading
import time

import app.embeddings as embeddings


class SlowPretendModel:
    loads = 0

    def __init__(self, *args, **kwargs):
        SlowPretendModel.loads += 1
        time.sleep(0.2)


def test_model_is_loaded_once_even_when_requests_arrive_together(monkeypatch):
    SlowPretendModel.loads = 0
    monkeypatch.setattr(embeddings, "TextEmbedding", SlowPretendModel)
    monkeypatch.setattr(embeddings, "_model", None)

    results = []
    start_together = threading.Barrier(8)

    def ask():
        start_together.wait()
        results.append(embeddings._get_model())

    threads = [threading.Thread(target=ask) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert SlowPretendModel.loads == 1
    assert len({id(model) for model in results}) == 1
