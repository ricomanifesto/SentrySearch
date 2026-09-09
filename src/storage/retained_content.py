"""Bounded, request-deadlined object reads without blocking the API event loop."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from threading import BoundedSemaphore
from typing import Callable, Iterable


class RetainedContentUnavailable(RuntimeError):
    """Eligibility cannot be established; this is not a policy exclusion."""


class RetainedContentReader:
    def __init__(self, *, max_workers: int = 4, timeout_seconds: float = 5.0):
        if timeout_seconds <= 0:
            raise ValueError("Content read deadline must be positive")
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="content-read"
        )
        self._slots = BoundedSemaphore(max_workers)
        self._timeout = timeout_seconds

    async def read_many(self, keys: Iterable[str], load: Callable[[str], str]) -> dict[str, str]:
        unique = list(dict.fromkeys(keys))
        deadline = asyncio.get_running_loop().time() + self._timeout

        async def read(key: str) -> str:
            while True:
                if asyncio.get_running_loop().time() >= deadline:
                    raise RetainedContentUnavailable("Report content temporarily unavailable")
                if self._slots.acquire(blocking=False):
                    break
                await asyncio.sleep(0.005)
            try:
                if asyncio.get_running_loop().time() >= deadline:
                    raise RetainedContentUnavailable("Report content temporarily unavailable")
                future = self._executor.submit(load, key)
            except BaseException:
                self._slots.release()
                raise
            # A request timeout cannot stop a running SDK call. Capacity belongs
            # to that call until its real completion, not to the awaiting task.
            future.add_done_callback(lambda _: self._slots.release())
            wrapped = asyncio.wrap_future(future)
            try:
                return await asyncio.wait_for(
                    asyncio.shield(wrapped),
                    timeout=max(0, deadline - asyncio.get_running_loop().time()),
                )
            except asyncio.TimeoutError as error:
                raise RetainedContentUnavailable(
                    "Report content temporarily unavailable"
                ) from error
            finally:
                # Consume late failures after request cancellation without
                # cancelling the underlying work or releasing its capacity.
                wrapped.add_done_callback(
                    lambda done: None if done.cancelled() else done.exception()
                )

        tasks = [asyncio.create_task(read(key)) for key in unique]
        try:
            return dict(zip(unique, await asyncio.gather(*tasks)))
        except BaseException:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise

    def close(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)


retained_content_reader = RetainedContentReader()
