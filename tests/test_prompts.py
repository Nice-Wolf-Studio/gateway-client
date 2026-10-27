"""Optional server `instructions` and MCP `prompts` in the declaration:
validated locally with the gateway's rules, sent in `register` only when
given, and announced with `prompts_changed` after an update."""

from __future__ import annotations

import asyncio

import pytest
from helpers import TOOLS, fake_gateway, make_service, recv_json, run, send_json

from gateway_client.protocol import MAX_INSTRUCTIONS_CHARS, Declaration


def _prompt(name="svc_review", **extra):
    prompt = {
        "name": name,
        "description": "Review a task.",
        "arguments": [{"name": "task_id", "description": "The task.", "required": True},
                      {"name": "tone", "description": "Optional tone."}],
        "messages": [{"role": "user",
                      "content": {"type": "text",
                                  "text": "Review task {{task_id}} in a {{tone}} tone."}}],
    }
    prompt.update(extra)
    return prompt


def _build(prompts=(), instructions=None, service="svc"):
    return Declaration.build(TOOLS, prompts=prompts, instructions=instructions,
                             service=service)


# --- old backends: nothing new on the wire -----------------------------------------

def test_register_frame_without_prompts_or_instructions_is_unchanged():
    frame = Declaration.build(TOOLS).register("svc", "c", "k")
    assert "prompts" not in frame and "instructions" not in frame


def test_register_frame_carries_instructions_and_prompts():
    frame = _build([_prompt()], "Use svc_review before closing a task.").register(
        "svc", "c", "k")
    assert frame["instructions"] == "Use svc_review before closing a task."
    assert frame["prompts"] == [_prompt()]


# --- instructions --------------------------------------------------------------------

@pytest.mark.parametrize("bad", [1, ["x"], {"a": 1}, True])
def test_instructions_must_be_a_string(bad):
    with pytest.raises(ValueError, match="instructions must be a string"):
        _build(instructions=bad)


def test_instructions_are_capped():
    _build(instructions="x" * MAX_INSTRUCTIONS_CHARS)
    with pytest.raises(ValueError, match=f"at most {MAX_INSTRUCTIONS_CHARS}"):
        _build(instructions="x" * (MAX_INSTRUCTIONS_CHARS + 1))


def test_blank_instructions_are_not_sent():
    frame = _build(instructions="   ").register("svc", "c", "k")
    assert "instructions" not in frame


# --- prompts ---------------------------------------------------------------------------

def test_prompt_name_needs_the_service_prefix():
    with pytest.raises(ValueError, match="must start with 'svc_'"):
        _build([_prompt(name="review")])
    with pytest.raises(ValueError, match="must start with 'svc_'"):
        _build([_prompt(name="svc_")])


def test_prompt_declared_twice_is_refused():
    with pytest.raises(ValueError, match="declared twice"):
        _build([_prompt(), _prompt()])


@pytest.mark.parametrize("field,value,match", [
    ("description", 3, "needs name, description and messages"),
    ("messages", [], "needs name, description and messages"),
    ("messages", "hi", "needs name, description and messages"),
    ("arguments", "x", "arguments must be a list"),
    ("arguments", [{"name": ""}], r"arguments\[0\] needs a name"),
    ("arguments", [{"name": "a b"}], r"arguments\[0\] needs a name"),
    ("arguments", [{"name": "a"}, {"name": "a"}], "argument 'a' declared twice"),
    ("arguments", [{"name": "a", "required": "yes"}], "required must be a boolean"),
    ("arguments", [{"name": "a", "description": 1}], "description must be a string"),
])
def test_malformed_prompt_is_refused(field, value, match):
    with pytest.raises(ValueError, match=match):
        _build([_prompt(**{field: value})])


@pytest.mark.parametrize("message", [
    {"role": "system", "content": {"type": "text", "text": "x"}},
    {"role": "user", "content": {"type": "image", "data": "x"}},
    {"role": "user", "content": {"type": "text"}},
    {"role": "user", "content": "x"},
    "x",
])
def test_prompt_message_must_be_a_user_or_assistant_text(message):
    with pytest.raises(ValueError, match=r"messages\[0\] needs role user or assistant"):
        _build([_prompt(messages=[message])])


def test_placeholder_must_name_a_declared_argument():
    bad = _prompt(messages=[{"role": "user",
                             "content": {"type": "text", "text": "Hi {{who}}"}}])
    with pytest.raises(ValueError, match="'who' is not a declared argument"):
        _build([bad])


def test_prompt_without_arguments_is_fine():
    prompt = {"name": "svc_hello", "description": "",
              "messages": [{"role": "assistant",
                            "content": {"type": "text", "text": "Hello."}}]}
    assert _build([prompt]).prompts == (prompt,)


def test_prompts_need_the_service_name_to_check_the_prefix():
    with pytest.raises(ValueError, match="service name"):
        Declaration.build(TOOLS, prompts=[_prompt()])


# --- GatewayService -------------------------------------------------------------------

def test_service_sends_instructions_and_prompts_and_announces_prompts_changed():
    new_prompt = _prompt(name="svc_close")

    async def main():
        loop = asyncio.get_running_loop()
        done = loop.create_future()
        registered = loop.create_future()

        async def handler(ws):
            first = await recv_json(ws)
            await send_json(ws, {"type": "registered"})
            registered.set_result(None)
            again = await recv_json(ws)
            await send_json(ws, {"type": "registered"})
            announce = await recv_json(ws)
            done.set_result((first, again, announce))
            await ws.wait_closed()

        async with fake_gateway(handler) as url:
            service = make_service(url, prompts=[_prompt()], instructions="Be brief.")
            runner = asyncio.create_task(service.run())
            await registered
            await service.wait_registered(5)
            await service.update(prompts=[_prompt(), new_prompt])
            result = await asyncio.wait_for(done, 5)
            await service.stop()
            await runner
            return result

    first, again, announce = run(main())
    assert first["instructions"] == "Be brief." and first["prompts"] == [_prompt()]
    assert [p["name"] for p in again["prompts"]] == ["svc_review", "svc_close"]
    assert again["instructions"] == "Be brief."
    assert announce == {"type": "prompts_changed"}


def test_service_checks_the_prompt_prefix_against_its_own_name():
    with pytest.raises(ValueError, match="must start with 'svc_'"):
        make_service("ws://127.0.0.1:1/backend", prompts=[_prompt(name="other_x")])


def test_update_instructions_reregisters_without_an_announcement():
    async def main():
        loop = asyncio.get_running_loop()
        done = loop.create_future()
        registered = loop.create_future()

        async def handler(ws):
            await recv_json(ws)
            await send_json(ws, {"type": "registered"})
            registered.set_result(None)
            again = await recv_json(ws)
            await send_json(ws, {"type": "registered"})
            try:
                extra = await asyncio.wait_for(recv_json(ws), 0.5)
            except asyncio.TimeoutError:
                extra = None
            done.set_result((again, extra))
            await ws.wait_closed()

        async with fake_gateway(handler) as url:
            service = make_service(url)
            runner = asyncio.create_task(service.run())
            await registered
            await service.wait_registered(5)
            await service.update(instructions="New text.")
            result = await asyncio.wait_for(done, 5)
            await service.stop()
            await runner
            return result

    again, extra = run(main())
    assert again["instructions"] == "New text."
    assert extra is None or extra.get("type") == "pong"


def test_announce_prompts_changed_when_not_registered_returns_false():
    service = make_service("ws://127.0.0.1:1/backend")
    assert run(service.send_prompts_changed()) is False
