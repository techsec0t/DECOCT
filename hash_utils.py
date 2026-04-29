import hashlib
import os

def calculate_hash(file_path):
    """Calculate SHA-256 hash of a local file."""
    if not os.path.isfile(file_path):
        return None
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for block in iter(lambda: f.read(4096), b""):
                sha256.update(block)
        return sha256.hexdigest()
    except Exception:
        return None
