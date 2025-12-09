import hashlib
from pathlib import Path
from typing import Any, Dict, List

class FileHandler:
    """Handle file operations and hashing"""
    
    @staticmethod
    def calculate_sha256(file_path: str) -> str:
        """
        Calculate SHA256 hash of a file
        
        Args:
            file_path: Path to the file
            
        Returns:
            SHA256 hash as hexadecimal string
        """
        sha256_hash = hashlib.sha256()
        
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        
        return sha256_hash.hexdigest()
    
    @staticmethod
    def get_files_from_directory(folder_path: str, recursive: bool = True) -> List[str]:
        """
        Get all files from a directory
        
        Args:
            folder_path: Path to the folder
            recursive: Whether to search recursively
            
        Returns:
            List of file paths
        """
        path = Path(folder_path)
        
        if not path.exists():
            return []
        
        if recursive:
            return [str(f) for f in path.rglob('*') if f.is_file()]
        else:
            return [str(f) for f in path.glob('*') if f.is_file()]
    
    @staticmethod
    def format_file_info(file_path: str, file_hash: str, vt_result: Dict[str, Any]) -> str:
        """
        Format file information for logging
        
        Args:
            file_path: Path to the file
            file_hash: SHA256 hash
            vt_result: VirusTotal analysis result
            
        Returns:
            Formatted string
        """
        status = vt_result.get('status', 'UNKNOWN')
        
        if status == 'INFECTED':
            return f"{status} | File={file_path} | SHA256={file_hash} | Malicious={vt_result.get('malicious', 0)} | Suspicious={vt_result.get('suspicious', 0)}"
        elif status == 'CLEAN':
            return f"{status} | File={file_path} | SHA256={file_hash}"
        else:
            return f"{status} | File={file_path} | SHA256={file_hash} | {vt_result.get('details', 'Error occurred')}"
