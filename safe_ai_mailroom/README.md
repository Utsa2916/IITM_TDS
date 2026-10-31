# Safe AI Mailroom

A Flask service implementing the `ga5-mailroom-action-gate/v2` propose/commit contract.

## Important
This is a starter implementation, not a guaranteed full-mark solution. The hidden dossiers require careful semantic decisions. Test the exact grader contract before spending a check. Never use real customer mail or secrets.

## Local setup (Windows PowerShell)

```powershell
py -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

Edit `.env` and set `AI_API_KEY`. For an OpenAI-compatible provider, set `AI_BASE_URL` and `AI_MODEL` to the provider's documented values.

Run:

```powershell
uvicorn main:application --host 0.0.0.0 --port 8000
```

Endpoint:
`http://127.0.0.1:8000/v1/mailroom/actions`

Health:
`http://127.0.0.1:8000/health`

## Render deployment

1. Push this folder to a new private GitHub repository.
2. In Render, create a Web Service from that repository.
3. Build command: `pip install -r requirements.txt`
4. Start command: `uvicorn main:application --host 0.0.0.0 --port $PORT`
5. Add environment variables:
   - `AI_BASE_URL`
   - `AI_API_KEY`
   - `AI_MODEL`
   - `DATABASE_PATH=/var/data/mailroom.sqlite3`
6. Attach a persistent disk mounted at `/var/data` (Render disk availability depends on plan).
7. Deploy and test `/health`.
8. Submit exactly `https://YOUR-SERVICE.onrender.com/v1/mailroom/actions`.

## Contract behavior

- `propose`: validates the envelope, computes SHA-256 over canonical dossiers, uses content cache, asks the configured AI for uncached decisions, validates frozen schemas, persists the evaluation and returns `awaiting_receipts`.
- `commit`: checks every receipt against the persisted proposal and verifies Ed25519 signatures using the supplied per-evaluation JWK. It atomically stores the terminal response.
- Exact propose/commit replays return stored responses. Changed propose content for an existing evaluation ID returns 409.
- No external email is sent. `executed` means the signed grader receipt accepted the proposal, as required by this assignment.

## Known implementation notes to review before submission

- The service uses SQLite and expects a persistent Render disk. The included Blueprint uses a paid Starter instance because Render persistent disks are not available on the free instance tier. If you use a free instance, move storage to a managed PostgreSQL database and adapt the storage layer.
- AI output is schema-validated but semantic correctness depends on the model and prompt. The hidden audit cases can expose weak reasoning; inspect model outputs and test with synthetic cases.
- The first uncached batch is sent in one model call. Keep the provider timeout below the grader's 55-second request deadline.
- The service intentionally fails closed (503) if the model is unavailable; it does not fabricate proposals.


## Uvicorn deployment

This project is Flask (WSGI), so `main.py` wraps the Flask app with `asgiref.wsgi.WsgiToAsgi`. Render starts it with Uvicorn using `main:application`. Do not use `uvicorn main:app`; the exported ASGI variable is named `application`.
