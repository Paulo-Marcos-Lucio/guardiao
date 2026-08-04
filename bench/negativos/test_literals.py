def test_login():
    password = "test123"
    secret = "SEGREDO"
    token = "changeme"
    api_key = "your-api-key-here"
    assert login(password)
