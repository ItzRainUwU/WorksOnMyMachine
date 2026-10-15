"""Application module with imports that only appeared to work on Windows."""

# The files on disk are config.py and routes.py.  These imports intentionally
# use the wrong case and fail on a case-sensitive Linux filesystem.
from webapp.Config import settings
from webapp.Routes import health


def application() -> dict[str, object]:
    return {"settings": settings(), "health": health()}
