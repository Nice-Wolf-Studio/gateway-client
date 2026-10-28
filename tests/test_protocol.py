"""Unit tests for protocol helpers: ToolResult, content_blocks, and parse_tool_result."""

from __future__ import annotations

import json
from gateway_client.protocol import ToolResult, content_blocks, parse_tool_result


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

    # dict with isError: True without content
    blocks, is_error = parse_tool_result({"isError": True, "code": 123})
    assert is_error is True
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
