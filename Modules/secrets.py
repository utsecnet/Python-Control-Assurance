"""
Helper to set passwords
"""
# Standard Python Libraries
import json
import sys

# Third partty Python Libraries

# Custom Python Libraries

secrets_file_location = './keys/secrets.json'
SECRETS = {}
try:
    with open(secrets_file_location) as config_file:
        SECRETS = json.loads(config_file.read())
except OSError:
    print("Error: {} does not exist.".format(secrets_file_location))
    sys.exit(1)
