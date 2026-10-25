# Sentinel AI — Backend

Real FastAPI + Playwright security scanning engine.

## Setup

```bash
cd backend
pip3 install -r requirements.txt
python3 -m playwright install chromium
```

## Run

```bash
python3 -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

API available at `http://localhost:8000`  
Docs at `http://localhost:8000/docs`

## Environment

`.env` is already configured with your OpenRouter key. To change the model, update `OPENAI_MODEL`.
Any model on [openrouter.ai/models](https://openrouter.ai/models) works — just use its full ID, e.g. `anthropic/claude-3.5-sonnet`.

## API

| Method | Path                     | Description                           |
| ------ | ------------------------ | ------------------------------------- |
| POST   | `/api/scans`             | Start a scan `{"url": "https://..."}` |
| GET    | `/api/scans`             | List all scans                        |
| GET    | `/api/scans/{id}`        | Get scan status + full report         |
| GET    | `/api/scans/{id}/stream` | SSE live progress stream              |
| DELETE | `/api/scans/{id}`        | Cancel a running scan                 |
| GET    | `/api/health`            | Health check                          |
