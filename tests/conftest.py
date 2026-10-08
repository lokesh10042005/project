import os


os.environ.setdefault(
    "JWT_SECRET_KEY",
    "test-only-jwt-signing-key-never-use-outside-tests",
)
