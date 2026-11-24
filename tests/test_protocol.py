"""Unit tests for protocol helpers: ToolResult, content_blocks, and parse_tool_result."""

from __future__ import annotations

import json
from gateway_client.protocol import (
    ToolResult,
    content_blocks,
    parse_tool_result,
    resource_contents,
)


def test_tool_result_defaults_and_properties():
    res = ToolResult("hello")
    assert res.content == "hello"
    assert res.is_error is False
    assert res.isError is False
    assert repr(res) == "ToolResult(content='hello', is_error=False)"

    err = ToolResult("failed", is_error=True)
    assert err.content == "failed"
    assert err.is_error is True
    assert err.isError is True
    assert repr(err) == "ToolResult(content='failed', is_error=True)"

    err_camel = ToolResult("failed", isError=True)
    assert err_camel.is_error is True
    assert err_camel.isError is True

    empty = ToolResult()
    assert empty.content == []
    assert empty.is_error is False

    assert ToolResult("a", is_error=True) == ToolResult("a", isError=True)
    assert ToolResult("a", is_error=True) != ToolResult("a", is_error=False)
    assert ToolResult("a") != "a"


def test_content_blocks_with_tool_result():
    res = ToolResult("text message")
    assert content_blocks(res) == [{"type": "text", "text": "text message"}]

    res_blocks = ToolResult([{"type": "text", "text": "block"}])
    assert content_blocks(res_blocks) == [{"type": "text", "text": "block"}]

    res_json = ToolResult({"a": 1})
    assert content_blocks(res_json) == [{"type": "text", "text": '{"a": 1}'}]


def test_content_blocks_with_dict_containing_is_error():
    # Issue #14: do NOT JSON-dump the entire dict into a text block when content is present!
    val = {"isError": True, "content": [{"type": "text", "text": "chat not found"}]}
    assert content_blocks(val) == [{"type": "text", "text": "chat not found"}]

    val_str = {"is_error": True, "content": "error string"}
    assert content_blocks(val_str) == [{"type": "text", "text": "error string"}]


def test_content_blocks_plain_values():
    assert content_blocks("plain") == [{"type": "text", "text": "plain"}]
    assert content_blocks([{"type": "text", "text": "ok"}]) == [{"type": "text", "text": "ok"}]
    assert content_blocks({"key": "val"}) == [{"type": "text", "text": '{"key": "val"}'}]


def test_parse_tool_result_with_tool_result():
    blocks, is_error = parse_tool_result(ToolResult("something broke", is_error=True))
    assert blocks == [{"type": "text", "text": "something broke"}]
    assert is_error is True

    blocks, is_error = parse_tool_result(ToolResult([{"type": "text", "text": "ok"}], is_error=False))
    assert blocks == [{"type": "text", "text": "ok"}]
    assert is_error is False


def test_parse_tool_result_with_dict():
    # dict with isError: True and content list
    blocks, is_error = parse_tool_result({
        "isError": True,
        "content": [{"type": "text", "text": "lookup miss"}],
    })
    assert blocks == [{"type": "text", "text": "lookup miss"}]
    assert is_error is True

    # dict with is_error: True and content str
    blocks, is_error = parse_tool_result({
        "is_error": True,
        "content": "not found",
    })
    assert blocks == [{"type": "text", "text": "not found"}]
    assert is_error is True

    # dict with isError: True without content is a plain domain dict (#51)
    blocks, is_error = parse_tool_result({"isError": True, "code": 123})
    assert is_error is False
    assert json.loads(blocks[0]["text"]) == {"isError": True, "code": 123}

    # dict with isError: False and content
    blocks, is_error = parse_tool_result({"isError": False, "content": "fine"})
    assert blocks == [{"type": "text", "text": "fine"}]
    assert is_error is False

    # standard business dict without isError / is_error
    blocks, is_error = parse_tool_result({"user": "alice", "active": True})
    assert is_error is False
    assert json.loads(blocks[0]["text"]) == {"user": "alice", "active": True}


def test_parse_tool_result_plain():
    blocks, is_error = parse_tool_result("hello world")
    assert blocks == [{"type": "text", "text": "hello world"}]
    assert is_error is False

    blocks, is_error = parse_tool_result([{"type": "text", "text": "list item"}])
    assert blocks == [{"type": "text", "text": "list item"}]
    assert is_error is False


# --- #50 & #51: plain JSON lists and domain dicts with is_error / isError ----------

def test_content_blocks_wraps_plain_json_lists_and_preserves_mcp_blocks():
    assert content_blocks([]) == []
    assert content_blocks([{"type": "text", "text": "hi"}]) == [{"type": "text", "text": "hi"}]
    assert content_blocks([{"type": "image", "data": "abc", "mimeType": "image/png"}]) == [
        {"type": "image", "data": "abc", "mimeType": "image/png"}
    ]
    assert content_blocks([1, 2, 3]) == [{"type": "text", "text": "[1, 2, 3]"}]
    assert content_blocks([{"id": 1}]) == [{"type": "text", "text": '[{"id": 1}]'}]
    assert content_blocks([{"type": ""}]) == [{"type": "text", "text": '[{"type": ""}]'}]


def test_resource_contents_wraps_plain_json_lists_and_preserves_mcp_contents():
    assert resource_contents([], "res://x", "text/plain") == []
    mcp = [{"uri": "res://x", "mimeType": "text/plain", "text": "hi"}]
    assert resource_contents(mcp, "res://x", "text/plain") == mcp
    assert resource_contents([1, 2, 3], "res://x", "text/plain") == [
        {"uri": "res://x", "mimeType": "application/json", "text": "[1, 2, 3]"}
    ]
    assert resource_contents([{"id": 1}], "res://x", "text/plain") == [
        {"uri": "res://x", "mimeType": "application/json", "text": '[{"id": 1}]'}
    ]


def test_parse_tool_result_preserves_domain_dicts_with_is_error_fields():
    msg_dict = {"id": 42, "author": "alice", "content": "hello", "is_error": False}
    blocks, is_error = parse_tool_result(msg_dict)
    assert is_error is False
    assert json.loads(blocks[0]["text"]) == msg_dict

    job_dict = {"job_id": "99", "is_error": True}
    blocks2, is_error2 = parse_tool_result(job_dict)
    assert is_error2 is False
    assert json.loads(blocks2[0]["text"]) == job_dict

    # Real ToolResult envelopes remain supported
    assert parse_tool_result({"content": "boom", "is_error": True}) == (
        [{"type": "text", "text": "boom"}], True
    )
    assert parse_tool_result({"content": [{"type": "text", "text": "boom"}], "isError": True}) == (
        [{"type": "text", "text": "boom"}], True
    )
    # Non-boolean isError is not treated as a ToolResult envelope
    nonbool = {"content": "boom", "isError": "yes"}
    blocks3, is_error3 = parse_tool_result(nonbool)
    assert is_error3 is False
    assert json.loads(blocks3[0]["text"]) == nonbool

    # Domain dict wrapped in ToolResult is never stripped
    wrapped = ToolResult(msg_dict, is_error=False)
    blocks4, is_error4 = parse_tool_result(wrapped)
    assert is_error4 is False
    assert json.loads(blocks4[0]["text"]) == msg_dict
    assert json.loads(content_blocks(wrapped)[0]["text"]) == msg_dict
    wrapped_exact = ToolResult({"content": "hello", "is_error": False}, is_error=True)
    blocks5, is_error5 = parse_tool_result(wrapped_exact)
    assert is_error5 is True
    assert json.loads(blocks5[0]["text"]) == {"content": "hello", "is_error": False}
