import asyncio
import random

from strands import tool
from ddgs.exceptions import RatelimitException, TimeoutException
from pydantic import BaseModel, Field
from ddgs import DDGS
from typing import List, Callable, Dict


class WebSearchHit(BaseModel):
    title: str = Field(description="Result title")
    url: str = Field(description="Result url")
    snippet: str = Field(description="Result snippet")


# 9.5.1 has backend: bing, brave, google, mojeek, mullvad_brave, mullvad_google, wikipedia, yahoo, yandex
def search_duckduckgo(query: str, num: int) -> List[WebSearchHit]:
    with DDGS() as ddg:
        results = ddg.text(query, backend="brave,bing,google", max_results=num)
        return [WebSearchHit(title=r["title"], url=r["href"], snippet=r["body"])
                for r in results]


def with_backoff(fn: Callable[..., List[WebSearchHit]],
                 retries: int = 4,
                 base: float = 1.5,
                 jitter: float = 0.3):
    """Decorate *fn* so it retries with exponential back-off on 429/5xx."""

    async def wrapper(*args, **kwargs):
        delay = base
        last_exc = None
        for attempt in range(retries + 1):
            try:
                async with asyncio.timeout(90):
                    hits = await asyncio.to_thread(fn, *args, **kwargs)
                if len(hits) == 0:
                    raise TimeoutException("no results")
                return hits
            except Exception as exc:
                last_exc = exc
                if attempt >= retries:
                    raise exc
                # Only retry obvious transient problems
                if isinstance(exc, RatelimitException):
                    pass
                elif isinstance(exc, TimeoutException):
                    pass
                else:
                    msg = str(exc).lower()
                    if "429" not in msg and "rate" not in msg and "timeout" not in msg \
                            and "temporarily unavailable" not in msg:
                        raise exc
                sleep_for = delay * (1 + random.uniform(-jitter, jitter))
                await asyncio.sleep(max(0.1, sleep_for))
                delay *= base
        raise last_exc

    return wrapper


@tool
async def web_search(
        query: str,
        limit: int = 20,
) -> List[Dict[str, str]]:
    """
    Searches the web with the provided query.

    Invoke this tool when the user needs to find general information on vulnerabilities, CVEs, published exploits,
    and instructions for using tools.

    Never include sensitive information such as personally identifiable information (PII), payment card data, health care
    information, etc.

    Args:
        query:
            | Example | Result |
            | ------- | ------ |
            | cats dogs | Results about cats or dogs |
            | "cats and dogs" | Results for exact term "cats and dogs". If no or few results are found, we'll try to show related results. |
            | ~"cats and dogs" | Experimental syntax: more results that are semantically similar to "cats and dogs", like "cats & dogs" and "dogs and cats" in addition to "cats and dogs". |
            | cats -dogs | Fewer dogs in results |
            | cats +dogs | More dogs in results |
            | cats filetype:pdf | PDFs about cats. Supported file types: pdf, doc(x), xls(x), ppt(x), html |
            | dogs site:example.com | Pages about dogs from example.com |
            | cats -site:example.com | Pages about cats, excluding example.com |
            | intitle:dogs | Page title includes the word "dogs" |
            | inurl:cats | Page URL includes the word "cats" |

        limit: The maximum number of results to return, defaults to 20
    Return:
        List of search results, each a Dict with title, url and snippet
    """
    limit = max(1, min(50, limit))

    search_fn = with_backoff(search_duckduckgo)
    hits = await search_fn(query, limit)

    return [dict(hit) for hit in hits]
