"""Project 4 JWT-shape detection; does not validate signatures."""

import re

JWT_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\."
    r"[A-Za-z0-9_-]+(?![A-Za-z0-9_-])"
)


def count_jwts(text: str) -> int:
    return len(JWT_PATTERN.findall(text))


def redact_output(text: str) -> str:
    return JWT_PATTERN.sub("[REDACTED]", text)


if __name__ == "__main__":
    sample = "Synthetic token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkZW1vIn0.fake_signature"
    print("Before:", sample)
    print("After: ", redact_output(sample))
