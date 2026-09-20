# JWKS Server

Name: Ananiya Getachew
EUID: aag0447

A simple JWKS (JSON Web Key Set) server built with Flask.

## Endpoints

- `GET /.well-known/jwks.json` — returns the JWKS document (public keys),
  excluding any expired keys.
- `POST /auth` — returns a signed JWT for a mock user (no credential
  checking, per assignment spec). Add `?expired` to receive a JWT signed
  with an already-expired key and an expired `exp` claim.

## Libraries used

- Flask — web server
- PyJWT — signing/decoding JWTs
- cryptography — RSA key generation
- pytest / pytest-cov — testing and coverage

## Setup

```bash
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Run

```bash
python app.py
```

Server listens on `http://localhost:8080`.

## Test

```bash
python -m pytest tests/ --cov=. --cov-report=term-missing
```

Current coverage: 98% (6/6 tests passing).

## Manual check

```bash
curl.exe -X POST http://localhost:8080/auth
curl.exe -X POST "http://localhost:8080/auth?expired=true"
curl.exe http://localhost:8080/.well-known/jwks.json
```

## Design notes

- Two RSA-2048 key pairs are generated at startup and stored in a global
  list in `keys.py`: one valid (expires in 1 hour) and one already
  expired (expired 1 hour ago). This lets the `expired` query parameter
  demonstrate key expiry without waiting.
- Each key gets a UUID `kid`, included in both the JWT header and the
  JWKS entry, so a verifier can match the two up.
- The JWKS endpoint filters out expired keys, so the expired key's
  public portion is intentionally never published there.

## Prompts used

- Give me a outline of jwks server
- What does --run do in Gradebot, and how do I point it at my venv's Python so my dependencies are available
- How do I make sure PyJWT puts the kid in the JWT header, not the payload
- Expired key still showing up in JWKS
- Confusing curl syntax in PowerShell
- What should go in my .gitignore for a Python Flask project so I don't commit my venv or cache files
- My JWKS endpoint is returning both my valid and expired keys
- PowerShell execution policy blocking venv activation

