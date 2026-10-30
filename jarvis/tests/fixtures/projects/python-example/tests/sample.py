from app import login

def test_login():
    assert login("Ada") == "Ada"
