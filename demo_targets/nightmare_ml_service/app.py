"""Small ML service fixture with the path and environment assumptions kept intact.

This file is intentionally written as if it only ever runs on the developer's
Windows workstation.  The Linux container in this fixture is expected to fail
until those assumptions are repaired.
"""

import os
from pathlib import Path


# These Windows-only paths are deliberately not portable to the container.
WINDOWS_MODEL_PATH = r"C:\Users\Dev\models\weights.bin"
BACKSLASH_MODEL_PATH = "data\\cache\\items.json"

# The service is expected to crash when the deployment forgot to provide this.
SECRET_MODEL_BUCKET = os.getenv("SECRET_MODEL_BUCKET")


def load_model() -> bytes:
    """Read the model from the workstation path used by the original service."""

    model_path = Path(WINDOWS_MODEL_PATH)
    print(f"loading {model_path} from {SECRET_MODEL_BUCKET}")
    return model_path.read_bytes()


def main() -> None:
    load_model()
    print("nightmare model service ready")


if __name__ == "__main__":
    main()
