from labhe import Init
from util_fpv import convert_to_json_serializable
import json

# Generate keys
privkey, pubkey = Init()

# Encrypt a value
cipher = pubkey.encrypt(1234)

# Create a test data dictionary
data = {
    "x": 42,
    "y": cipher
}

# Serialize to JSON
json_str = json.dumps(convert_to_json_serializable(data))
print(json_str)
