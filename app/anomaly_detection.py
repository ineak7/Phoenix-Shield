import re
import os

def detect_payload_anomaly(query_string: str) -> bool:
    """
    Detects SQL Injection, XSS, and command injection patterns in strings.
    Returns True if an anomaly (threat) is found.
    """
    if not query_string:
        return False
    
    # Common attack signatures
    attack_patterns = [
        r"(?i)(union\s+select)",
        r"(?i)(drop\s+table)",
        r"(?i)(<script>.*?</script>)",
        r"(?i)(or\s+['\"]?1['\"]?\s*=\s*['\"]?1)",
        r"(?i)(exec\s*\(.*\))",
        r"(?i)(admin\s*--)"
    ]
    
    for pattern in attack_patterns:
        if re.search(pattern, query_string):
            return True
            
    return False

def analyze_file_anomaly(filename: str, file_size_bytes: int) -> dict:
    """
    Analyzes uploaded files for suspicious extensions or abnormal sizes.
    """
    suspicious_extensions = ['.exe', '.bat', '.sh', '.scr', '.vbs', '.js']
    file_ext = os.path.splitext(filename)[1].lower() if '.' in filename else ""
    
    is_suspicious = file_ext in suspicious_extensions
    
    return {
        "filename": filename,
        "extension": file_ext,
        "size_bytes": file_size_bytes,
        "anomaly_flag": is_suspicious,
        "threat_level": "High (Malicious Extension)" if is_suspicious else "Normal"
    }