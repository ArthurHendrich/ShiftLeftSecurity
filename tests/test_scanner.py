from scanner import VulnerabilityScanner

def test_scanner_initialization(test_app):
    scanner = VulnerabilityScanner(test_app)
    assert scanner.app == test_app
    assert len(scanner.patterns) > 0


