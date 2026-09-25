import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.utils.security import create_access_token
from seed import seed_database

@pytest.fixture(scope="session", autouse=True)
def init_db():
    seed_database()

@pytest.fixture(scope="session")
def client():
    with TestClient(app) as c:
        yield c

@pytest.fixture(scope="session")
def auth_headers():
    token = create_access_token(data={"sub": "admin", "role": "admin"})
    return {"Authorization": f"Bearer {token}"}
