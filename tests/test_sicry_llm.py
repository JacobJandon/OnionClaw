# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 JacobJandon — https://github.com/JacobJandon/OnionClaw
"""The Anthropic branch of sicry._call_llm, driven with the SDK's real response types."""
import os
import sys
import types

import pytest

anthropic = pytest.importorskip("anthropic")
from anthropic.types import Message, TextBlock, ThinkingBlock, Usage  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import sicry  # noqa: E402


def _message(content, stop_reason):
    return Message(id="msg_test", type="message", role="assistant", model="claude-test",
                   content=content, stop_reason=stop_reason, stop_sequence=None,
                   usage=Usage(input_tokens=1, output_tokens=1))


@pytest.fixture
def reply(monkeypatch):
    """Make the next Anthropic call return the given response."""
    monkeypatch.setattr(sicry, "ANTHROPIC_API_KEY", "test-key")

    def use(response):
        class Client:
            def __init__(self, **_):
                self.messages = types.SimpleNamespace(create=lambda **kw: response)
        monkeypatch.setattr(anthropic, "Anthropic", Client)
        return sicry._call_llm("anthropic", "system", "prompt")
    return use


def test_reads_text_after_a_leading_thinking_block(reply):
    """Current models open with a thinking block, which has no .text; reading
    content[0] turned every analysis into an error string."""
    out = reply(_message([ThinkingBlock(type="thinking", thinking="", signature="s"),
                          TextBlock(type="text", text="Part one. "),
                          TextBlock(type="text", text="Part two.")], "end_turn"))
    assert out == "Part one. Part two."


def test_a_refusal_is_reported_not_returned_as_empty_text(reply):
    out = reply(_message([], "refusal"))
    assert "declined" in out and sicry.ANTHROPIC_MODEL in out


def test_a_refusal_names_its_category_when_the_sdk_provides_one(reply):
    out = reply(types.SimpleNamespace(stop_reason="refusal", content=[],
                                      stop_details=types.SimpleNamespace(category="cyber")))
    assert "(cyber)" in out


def test_a_truncated_response_says_so(reply):
    out = reply(_message([TextBlock(type="text", text="partial")], "max_tokens"))
    assert out.startswith("partial") and "max_tokens" in out


def test_a_plain_response_is_unchanged(reply):
    assert reply(_message([TextBlock(type="text", text="ok")], "end_turn")) == "ok"
