def test_redact():
    assert redact("/_internal/GFCHMJDGBKCPEGJMFCHFKPMLFNAGOFDA/intel/tabela") == "/_internal/<secret>/intel/tabela"
    assert redact("/_internal/PLACEHOLDER/x") == "/_internal/<secret>/x"
