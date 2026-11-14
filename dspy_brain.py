"""
DSPy LM backed by the Claude subscription CLI.

Wraps the local `claude` native binary (no API key) as a `dspy.BaseLM` via a
custom DSPy Engine. Because it goes through DSPy's normal call pipeline, every
call is recorded in DSPy's global history — so you can inspect the attacker
brain's reasoning with `dspy.inspect_history()` or `lm.history`.

Note: this captures the ATTACKER's reasoning (the brain we drive). It does NOT
reveal the target Riley's hidden reasoning — Riley is a remote black box, not a
dspy.LM. To steal Riley's traces use agent_reasoning_stealing.py.

Quick use:
    import dspy
    from dspy_brain import make_dspy_brain
    dspy.configure(lm=make_dspy_brain("sonnet"))
    cot = dspy.ChainOfThought("question -> answer")
    pred = cot(question="Name one risk of staff-impersonation attacks.")
    print(pred.reasoning, "=>", pred.answer)
    dspy.inspect_history(n=1)        # shows the prompt + the brain's reasoning

Drop-in for the agents' ClaudeLM (same .ask / .ask_json), but history-logged:
    from dspy_brain import DSPyBrain
    lm = DSPyBrain("sonnet")
    lm.ask("...")            # recorded in dspy history

Self-test / demo:
    python3 dspy_brain.py --demo
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from typing import Optional

import dspy
from dspy._vendor.lm15 import types as T

import btm
from agent import _find_claude_bin, _extract_json


# --------------------------------------------------------------------------- #
# Custom DSPy Engine: complete(Request) -> Response via the claude CLI
# --------------------------------------------------------------------------- #
def _flatten_parts(parts) -> str:
    out = []
    for p in parts or ():
        txt = getattr(p, "text", None)
        if txt:
            out.append(txt)
    return "\n".join(out)


def _render_messages(request: "T.Request") -> tuple[str, str]:
    """Collapse a DSPy Request into (prompt_text, system_text) for the CLI."""
    # system can be a str or a tuple of PromptPart
    sys_text = ""
    if isinstance(request.system, str):
        sys_text = request.system
    elif request.system:
        sys_text = _flatten_parts(request.system)

    lines = []
    for m in request.messages:
        role = getattr(m, "role", "user")
        body = _flatten_parts(m.parts)
        if not body:
            continue
        if role == "developer":          # treat developer turns as system
            sys_text = (sys_text + "\n" + body).strip()
        else:
            lines.append(f"{role.upper()}: {body}")
    return "\n\n".join(lines), sys_text


class ClaudeCLIEngine:
    """A DSPy Engine that answers with the Claude subscription CLI."""

    def __init__(self, timeout: int = 240):
        self.bin = _find_claude_bin()
        self.timeout = timeout

    def complete(self, request: "T.Request") -> "T.Response":
        prompt, system = _render_messages(request)
        model = request.model.split("/", 1)[-1]   # strip any "claude-cli/" prefix
        cmd = [self.bin, "-p", prompt, "--model", model,
               "--output-format", "json", "--allowed-tools", "",
               "--permission-mode", "plan"]
        if system:
            cmd += ["--append-system-prompt", system]

        text, usage = "", T.Usage()
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
            if proc.returncode == 0:
                try:
                    data = json.loads(proc.stdout)
                    text = (data.get("result") or "").strip()
                    u = data.get("usage") or {}
                    usage = T.Usage(input_tokens=u.get("input_tokens"),
                                    output_tokens=u.get("output_tokens"))
                except json.JSONDecodeError:
                    text = proc.stdout.strip()
            else:
                sys.stderr.write(f"[ClaudeCLIEngine] exit {proc.returncode}: {proc.stderr[:200]}\n")
        except subprocess.TimeoutExpired:
            sys.stderr.write("[ClaudeCLIEngine] timeout\n")

        return T.Response(
            id=None, model=request.model,
            message=T.Message(role="assistant", parts=(T.text(text),)),
            finish_reason="stop", usage=usage,
        )


# --------------------------------------------------------------------------- #
# BaseLM subclass that uses the engine (so DSPy records history for us)
# --------------------------------------------------------------------------- #
class ClaudeBrainLM(dspy.BaseLM):
    def __init__(self, model: str = "sonnet", **kwargs):
        super().__init__(model=f"claude-cli/{model}", model_type="chat",
                         engine=ClaudeCLIEngine(), cache=False, **kwargs)


def make_dspy_brain(model: str = "sonnet") -> ClaudeBrainLM:
    """Return a DSPy LM (claude subscription CLI) ready for dspy.configure(lm=...)."""
    return ClaudeBrainLM(model)


# --------------------------------------------------------------------------- #
# Target (Riley) as a dspy.LM — so its tool-call SQL lands in DSPy history and
# can be read back via dspy.inspect_history() / lm.history.
# --------------------------------------------------------------------------- #
def _user_text(request: "T.Request") -> str:
    """Concatenate the non-system message text to send to Riley, no role tags."""
    return "\n".join(_flatten_parts(m.parts) for m in request.messages
                     if getattr(m, "role", "user") not in ("developer",)).strip()


def _btm_last_tool_calls() -> list:
    try:
        return json.loads(btm.LOG.open().readlines()[-1])["response"].get("tool_calls") or []
    except Exception:  # noqa: BLE001
        return []


class RileyEngine:
    """DSPy Engine that calls the remote target Riley via btm.chat and carries
    its tool-call SQL into the Response (so it is recorded in DSPy history)."""

    def __init__(self, get_conversation):
        self._get_conv = get_conversation

    def complete(self, request: "T.Request") -> "T.Response":
        model = request.model.split("/", 1)[-1]
        msg = _user_text(request)
        try:
            reply = btm.chat(msg, model=model, conversation_id=self._get_conv())
        except Exception as e:  # noqa: BLE001
            reply = f"[target error: {e}]"
        parts = [T.text(reply)]
        for i, tc in enumerate(_btm_last_tool_calls()):
            if isinstance(tc, dict) and tc.get("name"):
                parts.append(T.ToolCallPart(id=f"tc{i}", name=tc["name"],
                                            input=(tc.get("args") or {})))
        return T.Response(
            id=btm.LAST_TURN_ID, model=request.model,
            message=T.Message(role="assistant", parts=tuple(parts)),
            finish_reason=("tool_call" if len(parts) > 1 else "stop"),
            usage=T.Usage(),
        )


class RileyLM(dspy.BaseLM):
    """Riley (the target) wrapped as a dspy.LM."""

    def __init__(self, model: str = "claude-haiku-5-5", **kwargs):
        self._conv = btm.new_conversation()
        super().__init__(model=f"riley/{model}", model_type="chat",
                         engine=RileyEngine(lambda: self._conv), cache=False, **kwargs)

    def new_conversation(self) -> str:
        self._conv = btm.new_conversation()
        return self._conv


def tool_calls_from_history(lm: Optional[dspy.BaseLM] = None) -> list[dict]:
    """Read the most recent entry's tool calls FROM DSPy HISTORY.

    This is the dspy.inspect_history() data path: it reads the same entries that
    dspy.inspect_history() prints, and returns [{name, args, sql}] per tool call.
    """
    if lm is not None:
        hist = lm.history
    else:
        from dspy.clients.base_lm import GLOBAL_HISTORY
        hist = GLOBAL_HISTORY
    if not hist:
        return []
    resp = hist[-1].get("response")
    parts = getattr(getattr(resp, "message", None), "parts", ()) or ()
    out = []
    for p in parts:
        name, inp = getattr(p, "name", None), getattr(p, "input", None)
        if name is not None and inp is not None:
            out.append({"name": name, "args": inp, "sql": (inp or {}).get("sql")})
    return out


# --------------------------------------------------------------------------- #
# Drop-in replacement for agent.ClaudeLM, but every call lands in dspy history
# --------------------------------------------------------------------------- #
class DSPyBrain:
    """Same .ask / .ask_json interface as agent.ClaudeLM, routed through DSPy."""

    def __init__(self, model: str = "sonnet", configure: bool = True):
        self.lm = make_dspy_brain(model)
        self.model = model
        if configure:
            dspy.configure(lm=self.lm)

    def ask(self, prompt: str, system: Optional[str] = None) -> str:
        text = f"{system}\n\n{prompt}" if system else prompt
        out = self.lm(text)                      # recorded in dspy.inspect_history()
        if isinstance(out, list):
            first = out[0] if out else ""
            return first if isinstance(first, str) else str(first)
        return str(out)

    def ask_json(self, prompt: str, system: Optional[str] = None) -> dict:
        raw = self.ask(prompt, system=system)        # single call
        return _extract_json(raw) or {"_raw": raw}


# --------------------------------------------------------------------------- #
def _demo(model: str) -> None:
    dspy.configure(lm=make_dspy_brain(model))

    print(f"== raw call (model={model}) ==")
    lm = dspy.settings.lm
    print("  ->", lm("Reply with exactly: PONG"))

    print("\n== ChainOfThought (reasoning captured) ==")
    cot = dspy.ChainOfThought("question -> answer")
    pred = cot(question="Name one risk of staff-impersonation prompt-injection, in one sentence.")
    print("  reasoning:", (pred.reasoning or "")[:200])
    print("  answer   :", (pred.answer or "")[:200])

    print("\n== dspy.inspect_history(n=1) ==")
    dspy.inspect_history(n=1)

    print(f"\n== lm.history has {len(lm.history)} entr(y/ies) ==")
    if lm.history:
        e = lm.history[-1]
        print("  keys:", sorted(e.keys()))
        print("  outputs[0][:160]:", str(e.get("outputs", [""])[0])[:160])


def main() -> None:
    ap = argparse.ArgumentParser(description="DSPy LM backed by the Claude CLI")
    ap.add_argument("--model", default="sonnet", help="sonnet | opus | haiku | full id")
    ap.add_argument("--demo", action="store_true", help="run a ChainOfThought + inspect_history")
    args = ap.parse_args()
    if args.demo:
        _demo(args.model)
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
