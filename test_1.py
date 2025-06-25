import app
import pytest
from config import Config

@pytest.fixture
def client():
    app.app.config.from_object(Config)
    with app.app.test_client() as client:
        yield client