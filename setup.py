"""Run once:  python3 setup.py   (asks for your name + API key, then tests the connection)"""
import getpass, subprocess, sys
from pathlib import Path

API_URL = "https://2-31-186-181.sslip.io"

print("\n=== Break the Model: setup ===\n")
def _have_deps():
    try:
        import requests, dotenv  # noqa: F401
        return True
    except ImportError:
        return False


if not _have_deps():
    print("Installing requirements...")
    base = [sys.executable, "-m", "pip", "install", "-q", "requests", "python-dotenv"]
    # Plain install, then per-user, then for Macs/Linux whose Python blocks pip (PEP 668).
    for extra in ([], ["--user"], ["--user", "--break-system-packages"], ["--break-system-packages"]):
        r = subprocess.run(base + extra, capture_output=True, text=True)
        if r.returncode == 0:
            break
    import importlib, site
    importlib.invalidate_caches()
    try:
        site.addsitedir(site.getusersitepackages())
    except Exception:  # noqa: BLE001
        pass
    if not _have_deps():
        sys.exit("\n❌ Could not install the 'requests' package automatically.\n"
                 "Run this, then run python3 setup.py again:\n"
                 f"   {sys.executable} -m pip install --user --break-system-packages requests python-dotenv\n"
                 f"(pip said: {r.stderr.strip()[-300:]})")

name = input("Your name: ").strip() or "anonymous"
key = getpass.getpass("Your API key: Anthropic (sk-ant-...), Groq (gsk_...) or Nebius (paste it; it stays hidden): ").strip()
if not key:
    sys.exit("No key entered. Use your team's Anthropic key, or get a free Groq key at console.groq.com -> API Keys.")

if key.startswith("sk-ant-"):
    provider, test_model = "anthropic", "claude-haiku-5-5"
elif key.startswith("gsk_"):
    provider, test_model = "groq", "groq/openai/gpt-oss-20b"
else:
    provider, test_model = "nebius", "Qwen/Qwen3-30B-A3B-Instruct-2507"
team = ""
Path(".env").write_text(f"YOUR_NAME={name}\nAPI_KEY={key}\nAPI_URL={API_URL}\n")
print(f"\nSaved ({provider.capitalize()} key). Testing the connection...")


import requests  # noqa: E402
try:
    r = requests.post(f"{API_URL}/chat", headers={"X-API-Key": key}, timeout=120, json={
        "participant": name, "model": test_model,
        "conversation_id": "setup-test", "message": "Hi! What are your visiting hours?"})
    data = r.json()
except Exception as e:  # noqa: BLE001
    sys.exit(f"\n❌ Could not reach the server ({e}). Check your internet, then run: python3 setup.py")

if r.status_code == 200:
    print(f"\n✅ It works! Riley says: {data['reply'][:200]}\n")
    print("Now start attacking:  python3 chat.py\n")
elif r.status_code == 429:
    print("\n✅ Your key works, but its rate limit is busy. Wait a minute, then run: python3 chat.py\n")
elif "401" in str(data) or "key" in str(data).lower():
    sys.exit("\n❌ Your key was rejected. Copy it again and run: python3 setup.py")
else:
    sys.exit(f"\n❌ Error {r.status_code}: {data}\nAsk an organizer for help.")