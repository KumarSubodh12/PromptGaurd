import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app import create_app, samples          # noqa: E402
from promptguard.config import MODEL_DIR      # noqa: E402
from promptguard.ml import Models             # noqa: E402
from promptguard.pipeline import Analyzer     # noqa: E402


@pytest.fixture(scope="session")
def models():
    return Models.load(MODEL_DIR / "promptguard.joblib")


@pytest.fixture(scope="session")
def analyzer(models):
    return Analyzer(models)


@pytest.fixture()
def client(tmp_path, models):
    app = create_app(tmp_path / "test.db", models)
    app.config["TESTING"] = True
    return app.test_client()


@pytest.fixture(scope="session")
def sample_map():
    return {s["id"]: s for s in samples()}
