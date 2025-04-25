import os
import re
import magic
import hashlib
import requests
from typing import Dict, List, Optional
from datetime import datetime

class FileScanner:
    def __init__(self):
        self.virus_total_api_key = os.getenv('VIRUS_TOTAL_API_KEY')
        self.supported_mime_types = [
            'application/pdf',
            'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'text/plain',
            'application/json',
            'text/html',
            'image/jpeg',
            'image/png',
            'image/gif'
        ]
        self.max_file_size_bytes = 50 * 1024 * 1024  # 50MB
        self.executable_extensions = ['.exe', '.dll', '.bat', '.cmd', '.msi', '.ps1', '.vbs', '.js']

    def calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of a file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def check_malware_patterns(self, content: bytes) -> Dict:
        """Check file content for common malware patterns."""
        content_str = content.decode('utf-8', errors='ignore')
        
        # Define malware patterns
        malware_patterns = {
            'shellcode': r'(%u[A-F0-9]{4}|\\u[A-F0-9]{4}|\\x[A-F0-9]{2}){10,}',
            'iframeInjection': r'<iframe.*?src=.*?(display:\s*none|height:\s*0|width:\s*0).*?>',
            'evalExecution': r'eval\s*\(.*?(base64|fromCharCode|escape|unescape).*?\)',
            'suspiciousRedirect': r'(window\.location|document\.location|location\.href|location\.replace)\s*=\s*["\']\S+["\']',
            'encodedScript': r'(base64_decode|str_rot13|gzinflate|gzuncompress|eval|assert|passthru)\s*\(',
            'obfuscatedJS': r'(\w+)\s*=\s*[\[{]\s*["\'\\]+.*?["\'\\]+\s*[}\]]\s*;.*?\1\s*\(',
            'maliciousFiles': r'\.(exe|dll|bat|sh|cmd|scr|ps1|vbs|hta|jar|msi|com|pif)$',
            'cryptoMining': r'(coinhive|cryptoloot|webminepool|cryptonight|minero|coinimp)',
            'dataExfiltration': r'(document\.cookie|localStorage|sessionStorage).*(send|post|fetch|ajax|xhr)',
            'sqlInjection': r'(\b(union|select|insert|update|delete|drop|alter)\b.*?(\b(from|into|table)\b))',
            'xssPatterns': r'(<script.*?>.*?(</script>)?|javascript:.*?|onload=.*?|onerror=.*?)',
            'phpShells': r'(c99|r57|shell|symlink|b374k|weevely|phpshell)',
            'suspiciousParams': r'\?(cmd|exec|system|passthru|eval|assert|shell|run|script)',
            'backdoorPatterns': r'(backdoor|rootkit|trojan|keylogger|spyware|botnet|RAT)',
            'sensitiveFiles': r'/(\.git|\.env|\.config|\.ssh|\.htpasswd|wp-config\.php|config\.php|database\.yml)'
        }

        detections = {}
        total_score = 0

        for pattern_name, pattern in malware_patterns.items():
            matches = len(re.findall(pattern, content_str, re.I))
            if matches > 0:
                detections[pattern_name] = matches
                total_score += matches * 10

        return {
            'detections': detections,
            'score': min(total_score, 100)
        }

    def scan_file(self, file_path: str) -> Dict:
        """Scan a file for security issues."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        # Check file size
        file_size = os.path.getsize(file_path)
        if file_size > self.max_file_size_bytes:
            raise ValueError(f"File size exceeds {self.max_file_size_bytes} bytes limit")

        # Get file type
        mime_type = magic.from_file(file_path, mime=True)
        if mime_type not in self.supported_mime_types:
            raise ValueError(f"Unsupported file type: {mime_type}")

        # Calculate file hash
        file_hash = self.calculate_file_hash(file_path)

        # Read file content for pattern matching
        with open(file_path, 'rb') as f:
            content = f.read()

        # Check for malware patterns
        pattern_analysis = self.check_malware_patterns(content)

        # Check file reputation if API key is available
        reputation_info = self.check_file_reputation(file_hash)

        return {
            'fileInfo': {
                'name': os.path.basename(file_path),
                'size': file_size,
                'type': mime_type,
                'hash': file_hash
            },
            'securityAnalysis': {
                'malwarePatterns': pattern_analysis['detections'],
                'riskScore': pattern_analysis['score'],
                'reputation': reputation_info
            },
            'timestamp': datetime.utcnow().isoformat()
        }

    def check_file_reputation(self, file_hash: str) -> Dict:
        """Check file reputation using VirusTotal API."""
        if not self.virus_total_api_key:
            return {
                'status': 'unknown',
                'confidence': 0,
                'sources': []
            }

        headers = {'x-apikey': self.virus_total_api_key}
        url = f'https://www.virustotal.com/vtapi/v2/file/report'
        params = {'resource': file_hash}
        
        try:
            response = requests.get(url, headers=headers, params=params)
            if response.status_code == 200:
                data = response.json()
                return {
                    'status': 'malicious' if data.get('positives', 0) > 0 else 'clean',
                    'confidence': data.get('positives', 0) / data.get('total', 1) * 100,
                    'sources': [{'name': 'VirusTotal', 'result': data}]
                }
        except Exception as e:
            print(f"Error checking file reputation: {e}")
            
        return {
            'status': 'unknown',
            'confidence': 0,
            'sources': []
        } 