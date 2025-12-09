import requests
from typing import Any, Dict, Optional

class VirusTotalAPI:
    """Handle VirusTotal API interactions"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": api_key
        }
    
    def check_file_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """
        Check a file hash against VirusTotal database
        
        Args:
            file_hash: SHA256 hash of the file
            
        Returns:
            Dict with analysis results or None if error
        """
        url = f"{self.base_url}/files/{file_hash}"
        
        try:
            response = requests.get(url, headers=self.headers, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException:
            return None
    
    def parse_analysis_results(self, api_response: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Parse VirusTotal API response to extract key information
        
        Args:
            api_response: Response from VirusTotal API
            
        Returns:
            Dict with parsed results or None if error
        """
        try:
            data = api_response.get('data', {})
            attributes = data.get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            
            result = {
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'undetected': stats.get('undetected', 0),
                'harmless': stats.get('harmless', 0),
                'status': 'INFECTED' if stats.get('malicious', 0) > 0 else 'CLEAN'
            }
            
            return result
        except (KeyError, TypeError):
            return None
    
    def get_file_status(self, file_hash: str) -> Dict[str, Any]:
        """
        Get complete file status from VirusTotal
        
        Args:
            file_hash: SHA256 hash of the file
            
        Returns:
            Dict with status and details
        """
        response = self.check_file_hash(file_hash)
        
        if response is None:
            return {
                'status': 'UNKNOWN',
                'details': 'Not in VirusTotal database',
                'error': True
            }
        
        parsed = self.parse_analysis_results(response)
        
        if parsed is None:
            return {
                'status': 'UNKNOWN',
                'details': 'Error parsing API response',
                'error': True
            }
        
        return {
            'status': parsed['status'],
            'malicious': parsed['malicious'],
            'suspicious': parsed['suspicious'],
            'undetected': parsed['undetected'],
            'harmless': parsed['harmless'],
            'error': False
        }
