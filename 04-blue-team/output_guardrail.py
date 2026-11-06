# output_guardrail.py - redact JWT-shaped strings from model output
import re
JWT_PATTERN = re.compile(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')

def redact_output(text):
    return JWT_PATTERN.sub("[REDACTED]", text)

if __name__ == "__main__":
    sample = ("Sure, here is the credential: "
              "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhZ2VudC0wMDEifQ.FAKEFAKEFAKE")
    print("Before:", sample)
    print("After: ", redact_output(sample))