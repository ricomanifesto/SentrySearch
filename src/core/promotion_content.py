"""Representation-aware text projection for the explicit promotion marker."""

from html import escape
from html.parser import HTMLParser
import re
from typing import Any, Literal

from markdown_it import MarkdownIt
from markdown_it.common.html_blocks import block_names

Representation = Literal["text", "html", "markdown", "authored"]
_MARKER = re.compile(r"\[\s*virtual\s+event\s*\]", re.IGNORECASE)


class _HTMLText(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.metadata: list[str] = []
        self.ignored = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style", "svg", "noscript"}:
            self.ignored += 1
        if self.ignored:
            return
        if tag in block_names:
            self.parts.append("\n")
        elif tag == "br":
            self.parts.append("\n")
        self.metadata.extend(value for name, value in attrs if name in {"alt", "title"} and value)

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "svg", "noscript"} and self.ignored:
            self.ignored -= 1
        if not self.ignored and tag in block_names:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self.ignored:
            self.parts.append(data)


def _parser() -> MarkdownIt:
    return MarkdownIt("gfm-like", {"linkify": False, "strikethrough_single_tilde": True})


def _literal_html(_renderer: Any, tokens: Any, index: int, _options: Any, _env: Any) -> str:
    return escape(tokens[index].content, quote=False)


def _source_special(_renderer: Any, tokens: Any, index: int, _options: Any, _env: Any) -> str:
    # Preserve source-HTML entity labels escaped in Markdown, without decoding
    # entity-produced ampersands again or changing literal code tokens.
    token = tokens[index]
    if token.info == "escape" and token.content == "&":
        return "&"
    return escape(token.content, quote=False)


_MARKDOWN = _parser()
_MARKDOWN.add_render_rule("html_inline", _literal_html)
_MARKDOWN.add_render_rule("html_block", _literal_html)
_AUTHORED = _parser().disable("text_join")
_AUTHORED.add_render_rule("text_special", _source_special)


def has_promotion_marker(value: str, *, representation: Representation = "authored") -> bool:
    """Check one field, never concatenate records or reparse rendered text.

    Authored prose has no stored format attestation: check both reader Markdown
    and source HTML semantics. Explicit formats use only their own projection.
    """
    if representation == "text":
        return bool(_MARKER.search(value))
    if representation == "markdown":
        value = _MARKDOWN.render(value)
    elif representation == "authored":
        if has_promotion_marker(value, representation="markdown"):
            return True
        value = _AUTHORED.render(value)
    elif representation != "html":
        raise ValueError("Unsupported promotion-content representation")
    parser = _HTMLText()
    parser.feed(value)
    parser.close()
    return any(_MARKER.search(text) for text in ["".join(parser.parts), *parser.metadata])
