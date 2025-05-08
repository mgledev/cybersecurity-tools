import re

def identify_hash_type(hash_value: str) -> str:
    """
    Simple hash type identifier based on length and pattern
    """
    h = hash_value.lower().strip()
    if not re.fullmatch(r"[a-f0-9]+", h):
        return "Unknown"

    length = len(h)
    if length == 32:
        return "MD5"
    elif length == 40:
        return "SHA1"
    elif length == 64:
        return "SHA256"
    else:
        return "Unknown"

def batch_identify(hashes: list[str]) -> dict:
    """
    Takes list of hash strings, returns dict: {hash: type}
    """
    return {h: identify_hash_type(h) for h in hashes}

# Example usage:
if __name__ == "__main__":
    test_hashes = [
        "098f6bcd4621d373cade4e832627b4f6",   # MD5
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",  # SHA1
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # SHA256
        "zzzz"  # invalid
    ]
    result = batch_identify(test_hashes)
    for h, t in result.items():
        print(f"{h} → {t}")
