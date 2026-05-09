import re
import os
import json
from datetime import datetime


class Session:
    def __init__(self, target, base_dir="data/sessions"):
        # Sanitize target: strip protocol and replace special chars
        safe_target = re.sub(r'^https?://', '', target)
        safe_target = safe_target.rstrip('/')
        safe_target = re.sub(r'[^\w\-.]', '_', safe_target)

        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"session_{safe_target}_{timestamp}.json"

        # Ensure base directory exists
        os.makedirs(base_dir, exist_ok=True)

        self.path = os.path.join(base_dir, filename)
        self.target = target
        self.data = {"target": target, "created": timestamp}
        self.save()

    def update(self, key, value):
        self.data[key] = value
        self.save()

    def get(self, key, default=None):
        return self.data.get(key, default)

    def save(self):
        # Ensure parent directory exists before writing
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w") as f:
            json.dump(self.data, f, indent=2, default=str)
