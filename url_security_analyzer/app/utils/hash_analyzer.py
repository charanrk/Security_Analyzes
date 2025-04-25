import re
import hashlib
import aiohttp
from typing import Dict, Optional, List
from datetime import datetime

class HashAnalyzer:
    HASH_PATTERNS = {
        'MD5': re.compile(r'^[a-f0-9]{32}$', re.I),
        'SHA1': re.compile(r'^[a-f0-9]{40}$', re.I),
        'SHA256': re.compile(r'^[a-f0-9]{64}$', re.I),
        'SHA512': re.compile(r'^[a-f0-9]{128}$', re.I)
    }

    def __init__(self):
        self.virus_total_api_key = None  # Set this from config

    @staticmethod
    def detect_hash_type(hash_string: str) -> Optional[str]:
        """Detect the type of hash based on its pattern."""
        hash_string = hash_string.strip()
        for hash_type, pattern in HashAnalyzer.HASH_PATTERNS.items():
            if pattern.match(hash_string):
                return hash_type
        return None

    async def check_reputation(self, hash_string: str) -> Dict:
        """Check hash reputation using VirusTotal API."""
        if not self.virus_total_api_key:
            return {
                'status': 'unknown',
                'confidence': 0,
                'sources': []
            }

        async with aiohttp.ClientSession() as session:
            headers = {'x-apikey': self.virus_total_api_key}
            url = f'https://www.virustotal.com/vtapi/v2/file/report'
            params = {'resource': hash_string}
            
            try:
                async with session.get(url, headers=headers, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        return {
                            'status': 'malicious' if data.get('positives', 0) > 0 else 'clean',
                            'confidence': data.get('positives', 0) / data.get('total', 1) * 100,
                            'sources': [{'name': 'VirusTotal', 'result': data}]
                        }
            except Exception as e:
                print(f"Error checking reputation: {e}")
                
        return {
            'status': 'unknown',
            'confidence': 0,
            'sources': []
        }

    async def get_detection_history(self, hash_string: str) -> List[Dict]:
        """Get detection history for the hash."""
        # This would typically query a database of previous detections
        return []

    async def analyze_hash(self, hash_string: str) -> Dict:
        """Analyze a hash string and return detailed information."""
        hash_type = self.detect_hash_type(hash_string)
        if not hash_type:
            raise ValueError("Invalid hash format")

        # Get reputation information
        reputation_info = await self.check_reputation(hash_string)
        
        # Get detection history
        detection_history = await this.get_detection_history(hash_string)

        return {
            'hashInfo': {
                'hash': hash_string,
                'type': hash_type,
                'length': f"{len(hash_string)} characters"
            },
            'analysisSummary': {
                'status': reputation_info['status'],
                'confidence': reputation_info['confidence'],
                'firstSeen': datetime.utcnow().isoformat()
            },
            'detailedAnalysis': {
                'reputation': reputation_info['sources'],
                'detectionHistory': detection_history
            }
        } 