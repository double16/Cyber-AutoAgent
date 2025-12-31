from __future__ import annotations

import json
import pytest
from pydantic import BaseModel

from modules.tools.browser import LLMClientJSONResponsePatch


class _FakeMessage:
    def __init__(self, content):
        self.content = content

    def __contains__(self, key: str) -> bool:
        return key == "content"


class _FakeChoice:
    def __init__(self, content):
        self.message = _FakeMessage(content)

    def __contains__(self, key: str) -> bool:
        return key == "message"


class _FakeResponse:
    def __init__(self, choices):
        self.choices = choices

    def __contains__(self, key: str) -> bool:
        return key == "choices"


class _InnerLLM:
    def __init__(self, response):
        self._response = response
        self.calls = []
        self.some_attr = "forwarded"

    async def create_response(self, **kwargs):
        self.calls.append(kwargs)
        return self._response


def _mk_patch_with_content(content: str) -> tuple[LLMClientJSONResponsePatch, _InnerLLM, _FakeResponse]:
    resp = _FakeResponse(choices=[_FakeChoice(content)])
    inner = _InnerLLM(resp)
    patch = LLMClientJSONResponsePatch(inner)
    return patch, inner, resp


def test___getattr___forwards_to_inner():
    patch, inner, _ = _mk_patch_with_content('{"a": 1}')
    assert patch.some_attr == "forwarded"
    inner.some_attr = "changed"
    assert patch.some_attr == "changed"


def test_strip_js_comments_removes_line_and_block_comments_but_keeps_strings():
    patch, _, _ = _mk_patch_with_content('{"a": 1}')

    s = r"""
    {
      // line comment
      "a": 1, /* block comment */
      "b": "http://example.com//path",
      "c": "/* not a comment */",
      "d": "quote: \"//\"",
      "e": "backslash: \\"
    }
    """

    stripped = patch.strip_js_comments(s)
    # comments removed
    assert "// line comment" not in stripped
    assert "block comment" not in stripped
    # string content preserved
    assert r'"b": "http://example.com//path"' in stripped
    assert r'"c": "/* not a comment */"' in stripped
    assert r'"d": "quote: \"//\""' in stripped
    assert r'"e": "backslash: \\"' in stripped

    # still valid JSON after stripping and trimming
    json.loads(stripped)


def test_extract_json_block_returns_original_when_no_codeblock():
    patch, _, _ = _mk_patch_with_content('{"a": 1}')
    text = 'no code block here: {"a": 1}'
    assert patch.extract_json_block(text) == text


def test_extract_json_block_picks_valid_json_block_after_comment_stripping():
    patch, _, _ = _mk_patch_with_content('{"a": 1}')

    text = """
    blah
    ```json
    {
      // comment
      "a": 1,
      "b": "hi//there"
    }
    ```
    trailing
    """
    extracted = patch.extract_json_block(text)
    # Should be the cleaned JSON payload (comments removed) that parses.
    obj = json.loads(extracted)
    assert obj == {"a": 1, "b": "hi//there"}


def test_extract_json_block_prefers_first_block_that_parses():
    patch, _, _ = _mk_patch_with_content('{"a": 1}')

    text = """
    ```json
    { this is not valid json }
    ```
    ```json
    {
      /* ok */
      "a": 1
    }
    ```
    """
    extracted = patch.extract_json_block(text)
    assert json.loads(extracted) == {"a": 1}


@pytest.mark.asyncio
async def test_create_response_no_response_format_does_not_modify():
    patch, inner, resp = _mk_patch_with_content("""
    ```json
    { "a": 1 }
    ```
    """)

    out = await patch.create_response(messages=[{"role": "user", "content": "x"}])
    assert out is resp
    # unchanged because response_format not set
    assert resp.choices[0].message.content.strip().startswith("```json")
    assert inner.calls and "messages" in inner.calls[0]


@pytest.mark.asyncio
async def test_create_response_missing_choices_returns_as_is():
    class _RespNoChoices:
        def __contains__(self, key: str) -> bool:
            return False

    inner = _InnerLLM(_RespNoChoices())
    patch = LLMClientJSONResponsePatch(inner)

    out = await patch.create_response(messages=[{"role": "user", "content": "x"}], response_format={"type": "json"})
    assert out is inner._response  # returned as-is


@pytest.mark.asyncio
async def test_create_response_non_list_choices_returns_as_is():
    resp = _FakeResponse(choices="not-a-list")  # type: ignore[arg-type]
    inner = _InnerLLM(resp)
    patch = LLMClientJSONResponsePatch(inner)

    out = await patch.create_response(messages=[{"role": "user", "content": "x"}], response_format={"type": "json"})
    assert out is resp
    assert resp.choices == "not-a-list"


@pytest.mark.asyncio
async def test_create_response_invalid_json_leaves_content_unchanged():
    patch, _, resp = _mk_patch_with_content("""
    ```json
    { not valid json }
    ```
    """)

    before = resp.choices[0].message.content
    await patch.create_response(messages=[{"role": "user", "content": "x"}], response_format={"type": "json"})
    after = resp.choices[0].message.content
    assert after == before


@pytest.mark.asyncio
async def test_create_response_extracts_codeblock_strips_comments_and_normalizes_json():
    patch, _, resp = _mk_patch_with_content(
        """
        Some text
        ```json
        {
          // comment
          "a": 1,
          /* block */
          "b": "hi//there"
        }
        ```
        More text
        """
    )

    await patch.create_response(messages=[{"role": "user", "content": "x"}], response_format={"type": "json"})

    # normalized json.dumps output (default separators/spaces)
    assert resp.choices[0].message.content == json.dumps({"a": 1, "b": "hi//there"}, ensure_ascii=False)


@pytest.mark.asyncio
async def test_create_response_when_content_is_plain_json_with_comments_normalizes():
    patch, _, resp = _mk_patch_with_content(
        """
        {
          // comment
          "a": 1,
          "b": "v"
        }
        """
    )

    await patch.create_response(messages=[{"role": "user", "content": "x"}], response_format={"type": "json"})
    assert resp.choices[0].message.content == json.dumps({"a": 1, "b": "v"}, ensure_ascii=False)


@pytest.mark.asyncio
async def test_create_response_when_content_is_plain_json_list_with_comments_normalizes():
    patch, _, resp = _mk_patch_with_content(
        """
        [
          // Main page title – tells you the purpose of the page
          "page.getByRole('heading', { name: 'Dalgna Challenges' })",
        
          // The primary form container – where any user input would be entered
          "page.locator('form')",
        
          // The decorative/branding image inside the form (if it conveys state)
          "page.locator('form >> img')",
        
          // Navigation link that likely leads to the next step or related content
          "page.getByRole('link', { name: 'Star Page' })",
        
          // The image inside the “Star Page” link (could be a button‑like icon)
          "page.getByRole('link', { name: 'Star Page' }).locator('img')"
        ]
        """
    )

    await patch.create_response(messages=[{"role": "user", "content": "x"}], response_format={"type": "json"})
    assert resp.choices[0].message.content == json.dumps([
        "page.getByRole('heading', { name: 'Dalgna Challenges' })",
        "page.locator('form')",
        "page.locator('form >> img')",
        "page.getByRole('link', { name: 'Star Page' })",
        "page.getByRole('link', { name: 'Star Page' }).locator('img')"
    ], ensure_ascii=False)


@pytest.mark.asyncio
async def test_create_response_ignores_blank_or_non_string_content():
    # blank string
    patch, _, resp = _mk_patch_with_content("   ")
    await patch.create_response(messages=[{"role": "user", "content": "x"}], response_format={"type": "json"})
    assert resp.choices[0].message.content == "   "

    # non-string content
    resp2 = _FakeResponse(choices=[_FakeChoice(content=None)])  # type: ignore[arg-type]
    inner2 = _InnerLLM(resp2)
    patch2 = LLMClientJSONResponsePatch(inner2)
    await patch2.create_response(messages=[{"role": "user", "content": "x"}], response_format={"type": "json"})
    assert resp2.choices[0].message.content is None


class _ElementsModel(BaseModel):
    elements: list[str]


@pytest.mark.asyncio
async def test_create_response_wraps_list_into_elements_when_response_format_requires_elements():
    # content is a JSON list (after comment stripping / extraction it's still a list)
    content = """
    ```json
    [
      "a",
      "b"
    ]
    ```
    """

    resp = _FakeResponse(choices=[_FakeChoice(content)])
    inner = _InnerLLM(resp)
    patch = LLMClientJSONResponsePatch(inner)

    await patch.create_response(
        messages=[{"role": "user", "content": "x"}],
        response_format=_ElementsModel,
    )

    assert resp.choices[0].message.content == json.dumps({"elements": ["a", "b"]}, ensure_ascii=False)


@pytest.mark.asyncio
async def test_create_response_does_not_wrap_when_elements_model_but_obj_is_not_list():
    content = """
    ```json
    { "elements": ["a", "b"] }
    ```
    """

    resp = _FakeResponse(choices=[_FakeChoice(content)])
    inner = _InnerLLM(resp)
    patch = LLMClientJSONResponsePatch(inner)

    await patch.create_response(
        messages=[{"role": "user", "content": "x"}],
        response_format=_ElementsModel,
    )

    assert resp.choices[0].message.content == json.dumps({"elements": ["a", "b"]}, ensure_ascii=False)


@pytest.mark.asyncio
async def test_create_response_does_not_wrap_list_when_response_format_not_elements_model():
    class _NonElementsModel(BaseModel):
        foo: int

    content = """
    ```json
    [
      1,
      2
    ]
    ```
    """

    resp = _FakeResponse(choices=[_FakeChoice(content)])
    inner = _InnerLLM(resp)
    patch = LLMClientJSONResponsePatch(inner)

    await patch.create_response(
        messages=[{"role": "user", "content": "x"}],
        response_format=_NonElementsModel,
    )

    # list stays list; normalized via json.dumps
    assert resp.choices[0].message.content == json.dumps([1, 2], ensure_ascii=False)


@pytest.mark.asyncio
async def test_create_response_elements_model_but_invalid_json_list_does_not_change():
    content = """
    ```json
    [
      "a",
      "b",
    ]
    ```
    """  # trailing comma -> invalid JSON

    resp = _FakeResponse(choices=[_FakeChoice(content)])
    inner = _InnerLLM(resp)
    patch = LLMClientJSONResponsePatch(inner)

    before = resp.choices[0].message.content
    await patch.create_response(
        messages=[{"role": "user", "content": "x"}],
        response_format=_ElementsModel,
    )
    after = resp.choices[0].message.content

    assert after == before
