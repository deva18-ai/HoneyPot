from detector.engine import max_severity

def test_severity():
    assert max_severity("LOW","HIGH") == "HIGH"
    assert max_severity("HIGH","LOW") == "HIGH"
