import app
import pytest
from config import Config

@pytest.fixture()
def application():
    application = app
    application.app.config.update(
        TESTING=True,
        DEBUG=True
    )
    yield application

@pytest.fixture()
def client(application):
    return application.app.test()
