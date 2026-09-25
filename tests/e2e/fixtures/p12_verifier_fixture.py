"""Publisher-only dependency wiring for a separately packaged verifier process."""
import json
import os
from p12_api import create_app

app = create_app(**json.loads(os.environ["P12_VERIFIER_CONFIG"]))
