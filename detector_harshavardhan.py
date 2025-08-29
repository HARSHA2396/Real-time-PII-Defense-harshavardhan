import re
import json
import pandas as pd
import sys

# -------------------------------
# Step 1: Define PII keywords
# -------------------------------
PII_KEYWORDS = {
    "name", "first_name", "last_name", "fullname",
    "email", "phone", "mobile", "contact",
    "address", "city", "state", "country", "zipcode", "pincode",
    "aadhar", "aadhaar", "passport", "pan", "ssn", "dob", "birth",
    "device_id", "imei", "uuid", "mac", "ip", "advertising_id"
}

# -------------------------------
# Step 2: Define regex patterns
# -------------------------------
PII_PATTERNS = {
    "phone": re.compile(r"\b\d{10}\b"),
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "aadhar": re.compile(r"\b\d{12}\b"),
    "ip": re.compile(r"(?:\d{1,3}\.){3}\d{1,3}"),
    "mac": re.compile(r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}"),
    "uuid": re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b")
}

# -------------------------------
# Step 3: Functions
# -------------------------------

def contains_pii(record: dict) -> bool:
    """
    Check if JSON record contains PII.
    """
    for key, value in record.items():
        key_lower = key.lower()
        val_str = str(value)

        # If key name itself is sensitive
        if key_lower in PII_KEYWORDS:
            return True

        # If value matches regex pattern
        for _, pattern in PII_PATTERNS.items():
            if pattern.search(val_str):
                return True

    return False


def redact_value(value: str) -> str:
    """
    Mask sensitive values.
    """
    val_str = str(value)

    # Phone number
    if re.fullmatch(PII_PATTERNS["phone"], val_str):
        return val_str[:2] + "XXXXXX" + val_str[-2:]

    # Aadhaar
    if re.fullmatch(PII_PATTERNS["aadhar"], val_str):
        return "XXXXXXXX" + val_str[-4:]

    # Email
    if re.fullmatch(PII_PATTERNS["email"], val_str):
        user, domain = val_str.split("@")
        return user[0] + "XXX@" + domain

    # IP address
    if re.fullmatch(PII_PATTERNS["ip"], val_str):
        parts = val_str.split(".")
        return ".".join(parts[:3] + ["XXX"])

    # UUID
    if re.fullmatch(PII_PATTERNS["uuid"], val_str):
        return val_str[:8] + "-XXXX-XXXX-XXXX-" + val_str[-12:]

    # MAC address
    if re.fullmatch(PII_PATTERNS["mac"], val_str):
        return val_str[:9] + "XX:XX:XX"

    # Device IDs / misc
    if any(k in val_str.lower() for k in ["dev", "imei", "uuid", "mac"]):
        return val_str[:3] + "XXXXX" + val_str[-2:]

    return value


def redact_record(record: dict) -> dict:
    """
    Apply redaction to sensitive fields inside JSON record.
    """
    redacted = {}
    for key, value in record.items():
        key_lower = key.lower()
        if key_lower in PII_KEYWORDS or any(p.search(str(value)) for p in PII_PATTERNS.values()):
            redacted[key] = redact_value(value)
        else:
            redacted[key] = value
    return redacted


# -------------------------------
# Step 4: Main
# -------------------------------
def main(input_file: str, output_file: str):
    df = pd.read_csv(input_file)

    # Handle both possible JSON column names
    if "data_json" in df.columns:
        json_col = "data_json"
    elif "Data_json" in df.columns:
        json_col = "Data_json"
    else:
        raise KeyError("No JSON column found in CSV. Expected 'data_json' or 'Data_json'.")

    results = []
    for idx, row in df.iterrows():
        try:
            data = json.loads(row[json_col])
        except Exception as e:
            print(f"[!] Skipping row {idx} due to JSON error: {e}")
            results.append({
                "record_id": row.get("record_id", idx + 1),
                "redacted_data_json": "{}",
                "is_pii": False
            })
            continue

        pii_found = contains_pii(data)
        redacted_data = redact_record(data) if pii_found else data

        results.append({
            "record_id": row.get("record_id", idx + 1),
            "redacted_data_json": json.dumps(redacted_data),
            "is_pii": pii_found
        })

    out_df = pd.DataFrame(results)
    out_df.to_csv(output_file, index=False)
    print(f"[+] Output saved to {output_file}")


# -------------------------------
# Entry Point
# -------------------------------
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python detector_full_candidate_name.py <input_csv> <output_csv>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])
