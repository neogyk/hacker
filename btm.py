"""Break the Model — tiny client. Every call is also saved to logs/my_attempts.jsonl."""
import json, os, time, uuid
from pathlib import Path
import requests
from dotenv import load_dotenv, dotenv_values

load_dotenv()
API = os.environ["API_URL"].rstrip("/")
NAME = os.environ.get("YOUR_NAME", "")
# Per-provider keys. Server (commit 8894e0a) reads X-API-Key and routes by the key
# itself. We keep one key per provider and pick the one matching the target model,
# so we can attack Nebius, Groq and (when live) Claude/Anthropic in one session.
# SECURITY: read these secrets ONLY from the local .env file, never from the process
# environment — so this client can never pick up and forward an unrelated session key
# (e.g. the machine's own ANTHROPIC_API_KEY) to the hackathon server.
_ENV = dotenv_values(Path(__file__).parent / ".env")
_NEBIUS_KEY = _ENV.get("NEBIUS_API_KEY") or _ENV.get("API_KEY") or ""
_GROQ_KEY = _ENV.get("GROQ_API_KEY") or ""
_ANTHROPIC_KEY = _ENV.get("ANTHROPIC_API_KEY") or ""
KEY = _NEBIUS_KEY  # back-compat default


def _key_for(model):
    """Return the provider key that matches the model (never printed/logged)."""
    m = (model or "").lower()
    if m.startswith("groq/") and _GROQ_KEY:
        return _GROQ_KEY
    if ("claude" in m or "anthropic" in m) and _ANTHROPIC_KEY:
        return _ANTHROPIC_KEY
    return _NEBIUS_KEY


LOG = Path(__file__).parent / "logs" / "my_attempts.jsonl"
LOG.parent.mkdir(exist_ok=True)
LAST_TURN_ID = None


def list_models():
    return [m["id"] for m in requests.get(f"{API}/models", timeout=30).json()["models"]]


def new_conversation():
    return "conv_" + uuid.uuid4().hex[:12]


def chat(message, model, conversation_id=None, level=None):
    """Send one message. Reuse the same conversation_id to keep talking in one conversation.
    Pass level=1|2|3 to select Riley's guardrail tier (only sent when set)."""
    body = {"participant": NAME, "model": model,
            "conversation_id": conversation_id or new_conversation(), "message": message}
    if level is not None:
        body["level"] = level
    r = requests.post(f"{API}/chat", json=body,
                      headers={"X-API-Key": _key_for(model)}, timeout=300)
    data = r.json()
    with LOG.open("a") as f:
        f.write(json.dumps({"ts": time.strftime("%H:%M:%S"), "request": body, "response": data}) + "\n")
    if r.status_code != 200:
        raise RuntimeError(f"Error {r.status_code}: {data}")
    for tc in data.get("tool_calls") or []:
        print(f"  [Riley used tool: {tc['name']}]")
    global LAST_TURN_ID
    LAST_TURN_ID = data["turn_id"]
    return data["reply"]
