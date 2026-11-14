"""Break the Model — tiny client. Every call is also saved to logs/my_attempts.jsonl."""
import json, os, time, uuid
from pathlib import Path
import requests
from dotenv import load_dotenv

load_dotenv()
API = os.environ["API_URL"].rstrip("/")
NAME = os.environ.get("YOUR_NAME", "")
KEY = os.environ.get("API_KEY") or os.environ.get("NEBIUS_API_KEY") or ""
TEAM = os.environ.get("TEAM_CODE", "")
if not KEY and not TEAM:
    raise KeyError("run setup first")
PROVIDER = ("anthropic" if KEY.startswith("sk-ant-") else "groq" if KEY.startswith("gsk_")
            else "nebius" if KEY else None)
LOG = Path(__file__).parent / "logs" / "my_attempts.jsonl"
LOG.parent.mkdir(exist_ok=True)
LAST_TURN_ID = None

ORDER = {"small": 0, "medium": 1, "large": 2, "very large": 3}


def list_models():
    """Models that work with YOUR key, weakest first: [(model_id, size), ...]"""
    ms = requests.get(f"{API}/models", timeout=30).json()["models"]
    mine = [m for m in ms if m.get("provider") == PROVIDER or (TEAM and m.get("provider") == "anthropic")]
    mine.sort(key=lambda m: ORDER.get(m.get("tier"), 9))
    return [(m["id"], m.get("tier", "")) for m in mine]


def new_conversation():
    return "conv_" + uuid.uuid4().hex[:12]


def chat(message, model, conversation_id=None):
    """Send one message. Reuse the same conversation_id to keep talking in one conversation."""
    global LAST_TURN_ID
    body = {"participant": NAME, "team_token": TEAM, "model": model,
            "conversation_id": conversation_id or new_conversation(), "message": message}
    r = requests.post(f"{API}/chat", json=body, headers={"X-API-Key": KEY} if KEY else {}, timeout=300)
    data = r.json()
    with LOG.open("a") as f:
        f.write(json.dumps({"ts": time.strftime("%H:%M:%S"), "request": body, "response": data}) + "\n")
    if r.status_code != 200:
        err = data.get("error")
        raise RuntimeError(err.get("message") if isinstance(err, dict) else err)
    for tc in data.get("tool_calls") or []:
        print(f"  [Riley used tool: {tc['name']}]")
    LAST_TURN_ID = data["turn_id"]
    return data["reply"]