"""GitHub response decoder: a GitHub 2xx payload -> the shared
:class:`~kiro_crew.connections.control_plane.result.OperationResult`.

WHAT THIS OWNS
==============
W01's production transport (``control_plane/production.py``) injects the
2xx -> ``OperationResult`` mapping as a
:data:`~kiro_crew.connections.control_plane.production.ResultDecode`, because
where the continuation cursor lives is the vendor's spelling, not the transport's
(``@odata.nextLink`` for Graph, a ``Link`` response header or a GraphQL ``after``
for GitHub). This module is GitHub's decode. It is the piece that lets a page
walk over GitHub actually advance: the executor's :class:`PageWalk` reads
``OperationResult["next_cursor"]`` to decide whether another page is owed, and
this decoder is what puts GitHub's next-page position there.

HOW IT STAYS HONEST
===================
* **The cursor is the provider's own opaque continuation, verbatim.** For a REST
  page it is the whole ``rel="next"`` URL out of the ``Link`` header (read with
  the existing :func:`~kiro_crew.connections.vendors.github.pagination.next_page_url`);
  for a GraphQL-backed tool it is the opaque ``after`` token the body carries.
  Neither is reconstructed -- the locator re-sends whichever one this returns
  unchanged, so a walk neither drops nor rebuilds a page position.
* **``next_cursor=None`` means the walk is DONE, and only when the provider says
  so.** A REST reply with no ``rel="next"`` is the terminal page (its ``Link``
  header omits ``next``); a cursor reply whose ``hasNextPage`` is false, or which
  carries no ``endCursor``, is terminal. This is the SAME honesty W01's
  :func:`~kiro_crew.connections.control_plane.production.neutral_decode_detail`
  enforces -- ``None`` is a fact read off the reply, never a default assumed for
  a body this module did not inspect.
* **Byte/JSON mechanics reuse W01's helper.** The body is parsed with
  :func:`~kiro_crew.connections.control_plane.production.decode_json_body`, the
  helper the production module exposes for exactly a vendor decode, so this
  module does not re-implement the JSON-or-empty handling.

WHAT THIS DELIBERATELY DOES NOT OWN
===================================
No error classification -- a non-2xx never reaches a ``ResultDecode`` (the
executor's :func:`classify_error` and GitHub's ``classify_github_failure`` own
that). No retry, no backoff, no auth. A structurally impossible success body
(a cursor tool whose ``pageInfo`` is not an object) is a :class:`GithubDecodeError`
shaping fault, mirroring ``graph/payload.GraphPayloadError`` -- never a vendor
error taxonomy grown here.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional

from kiro_crew.connections.control_plane.production import (
    HttpReply,
    decode_json_body,
)
from kiro_crew.connections.control_plane.result import OperationResult
from kiro_crew.connections.vendors.github.pagination import next_page_url


class GithubDecodeError(ValueError):
    """A GitHub 2xx body was structurally malformed for its declared shape.

    A shaping fault only, mirroring ``graph/payload.GraphPayloadError``: a cursor
    tool whose ``pageInfo`` is present but not an object, for instance. A vendor
    HTTP failure is W01's typed boundary and never reaches a decode, so this is
    NOT a vendor-error class.
    """


def _result(*, complete: bool, next_cursor: Optional[str]) -> OperationResult:
    """Build the L01 envelope. ``complete`` picks the success status.

    ``ok`` when the collection is exhausted (or a single-object read), ``partial``
    when a cursor remains -- the same success-side ``partial`` W01's
    ``neutral_decode_detail`` uses for "more may follow", never the error-class
    ``partial``. ``next_cursor`` is the opaque continuation or ``None``.
    """

    return {"status": "ok" if complete else "partial", "next_cursor": next_cursor}


def decode_rest_page(reply: HttpReply) -> OperationResult:
    """Decode a REST ``page``/``perPage`` GitHub reply.

    The continuation is GitHub's ``Link`` response header: its ``rel="next"`` URL
    is the whole next-page request line, surfaced VERBATIM as the cursor so the
    locator re-sends it unchanged. No ``rel="next"`` means the terminal page, so
    ``next_cursor`` is ``None`` and the status is ``ok``. The body is not read
    for paging -- GitHub REST carries the position in the header, not the body --
    which keeps this decode from guessing a cursor out of a payload.
    """

    link_header = _header(reply.headers, "Link")
    next_url = next_page_url(link_header)
    return _result(complete=next_url is None, next_cursor=next_url)


def decode_cursor_page(reply: HttpReply) -> OperationResult:
    """Decode a GraphQL-backed cursor (``after``) GitHub reply.

    The GraphQL connection carries paging in the body's ``pageInfo``
    (``hasNextPage`` / ``endCursor``). This reads them from wherever the tool
    nests the connection: it walks the parsed body for the first ``pageInfo``
    object rather than assuming one query's field path, because github-mcp-server
    tools wrap the connection differently. When ``hasNextPage`` is true and an
    ``endCursor`` is present, that opaque cursor is the continuation; otherwise
    the walk is done (``next_cursor=None``, status ``ok``). A ``pageInfo`` that
    is present but not an object is a :class:`GithubDecodeError`.
    """

    body = decode_json_body(reply)
    page_info = _find_page_info(body)
    if page_info is None:
        # No pageInfo at all: a non-paginated cursor reply or an empty page.
        return _result(complete=True, next_cursor=None)
    if not isinstance(page_info, Mapping):
        raise GithubDecodeError("GraphQL 'pageInfo' is present but is not an object")
    has_next = bool(page_info.get("hasNextPage"))
    end_cursor = page_info.get("endCursor")
    if has_next and isinstance(end_cursor, str) and end_cursor:
        return _result(complete=False, next_cursor=end_cursor)
    return _result(complete=True, next_cursor=None)


def _find_page_info(body: Any) -> Optional[Any]:
    """Return the first ``pageInfo`` value found anywhere in ``body``, or ``None``.

    A breadth-first walk over the parsed JSON: github-mcp-server's GraphQL tools
    nest the connection under different field paths
    (``data.repository.issues.pageInfo`` etc.), so keying on one fixed path would
    break the moment a tool nested it elsewhere. Returns the value under the
    first ``pageInfo`` key encountered; the caller validates it is an object.
    """

    queue: list[Any] = [body]
    while queue:
        node = queue.pop(0)
        if isinstance(node, Mapping):
            if "pageInfo" in node:
                return node["pageInfo"]
            queue.extend(node.values())
        elif isinstance(node, list):
            queue.extend(node)
    return None


def decode_single(reply: HttpReply) -> OperationResult:
    """Decode a single-object / unpaginated GitHub reply.

    A ``Pagination.NONE`` operation returns one object or an unpaginated whole
    (a file, a git tree, a rate-limit snapshot). There is no continuation, so
    the result is always ``ok`` with ``next_cursor=None``. The body is parsed for
    validity (a malformed body would be a shaping fault) but carries no cursor.
    """

    decode_json_body(reply)  # parse for validity; a non-JSON 2xx body is tolerated as {}
    return _result(complete=True, next_cursor=None)


def _header(headers: Mapping[str, str], name: str) -> Optional[str]:
    """Case-insensitive header lookup (HTTP header names are case-insensitive)."""

    lowered = name.lower()
    for key, value in headers.items():
        if key.lower() == lowered:
            return value
    return None


__all__ = [
    "GithubDecodeError",
    "decode_cursor_page",
    "decode_rest_page",
    "decode_single",
]
