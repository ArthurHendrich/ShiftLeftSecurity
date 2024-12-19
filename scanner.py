import os
import re
from datetime import datetime
from models import Vulnerability
from database import db

def is_library_file(file_path):
    """Check if a file is from a library/dependency"""
    library_indicators = [
        '/venv/',
        '.venv/',
        '/site-packages/',
        '/dist-packages/',
        '/node_modules/',
        'lib/python'
    ]
    return any(indicator in file_path for indicator in library_indicators)

class VulnerabilityScanner:
    def __init__(self, app):
        self.app = app
        self.patterns = {
            'hardcoded_secret': (r'(password|secret|key)\s*=\s*["\'][^"\']+["\']', 'Hardcoded Secrets', 'High'),
            'sql_injection': (r'execute\([\'"]SELECT.*\+.*[\'"]\)', 'SQL Injection', 'High'),
            'xss': (r'innerHTML|document\.write\(', 'Cross-Site Scripting (XSS)', 'High'),
            'weak_crypto': (r'md5|sha1', 'Weak Cryptography', 'Medium'),
            'debug_exposure': (r'app\.debug\s*=\s*True|DEBUG\s*=\s*True', 'Debug Information Exposure', 'Medium'),
        }
        
    def scan_file(self, filepath):
        try:
            with open(filepath, 'r') as file:
                content = file.read()
                for vuln_type, (pattern, desc, severity) in self.patterns.items():
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        # Check if vulnerability already exists
                        existing = Vulnerability.query.filter_by(
                            type=vuln_type,
                            location=f"{filepath}:{match.start()}"
                        ).first()
                        
                        if not existing:
                            vuln = Vulnerability(
                                type=vuln_type,
                                severity=severity,
                                description=f"{desc} found in pattern: {match.group()}",
                                location=f"{filepath}:{match.start()}",
                                discovered_at=datetime.utcnow(),
                                status='open',
                                source_type='library' if is_library_file(filepath) else 'application'
                            )
                            db.session.add(vuln)
                            db.session.commit()
        except Exception as e:
            print(f"Error scanning file {filepath}: {str(e)}")

    def scan_directory(self, directory='.'):
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith(('.py', '.js', '.html')):
                    filepath = os.path.join(root, file)
                    self.scan_file(filepath)

    def get_stats(self):
        total = Vulnerability.query.count()
        high = Vulnerability.query.filter_by(severity='High').count()
        medium = Vulnerability.query.filter_by(severity='Medium').count()
        low = Vulnerability.query.filter_by(severity='Low').count()
        return {
            'total': total,
            'high': high,
            'medium': medium,
            'low': low
        }
