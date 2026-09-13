"""Coordinated Watchtower startup, supervision, and graceful shutdown."""

from __future__ import annotations

import asyncio
import logging
import signal
import threading
from typing import Callable, List, Optional

from .config import settings, setup_logging
from .redis_client import wait_for_redis

logger = logging.getLogger("watchtower.main")


class _ShutdownController:
    def __init__(self) -> None:
        self._stop_event = threading.Event()
        self._async_event: Optional[asyncio.Event] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._failure: Optional[tuple[str, str]] = None
        self._lock = threading.Lock()

    @property
    def stop_event(self) -> threading.Event:
        return self._stop_event

    @property
    def failure(self) -> Optional[tuple[str, str]]:
        with self._lock:
            return self._failure

    def bind_async(
        self,
        event: asyncio.Event,
        loop: asyncio.AbstractEventLoop,
    ) -> None:
        self._async_event = event
        self._loop = loop

    def trigger(self, reason: str = "shutdown requested") -> None:
        first_trigger = not self._stop_event.is_set()
        self._stop_event.set()
        if first_trigger:
            logger.info("Shutdown requested | reason=%s", reason)
        if self._async_event is not None and self._loop is not None:
            try:
                self._loop.call_soon_threadsafe(self._async_event.set)
            except RuntimeError:
                # The event loop may already be closed during interpreter exit.
                pass

    def fail(self, component: str, exc: BaseException) -> None:
        error_type = type(exc).__name__
        with self._lock:
            if self._failure is None:
                self._failure = (component, error_type)
        logger.exception(
            "Component failed | component=%s error_type=%s",
            component,
            error_type,
        )
        self.trigger(f"{component} failed")


def _thread_runner(
    controller: _ShutdownController,
    component: str,
    target: Callable[[threading.Event], None],
) -> None:
    try:
        target(controller.stop_event)
    except BaseException as exc:
        controller.fail(component, exc)


def _run_correlator(stop_event: threading.Event) -> None:
    from .correlator import correlate

    correlate(stop_event=stop_event)


def _run_code_watcher(stop_event: threading.Event) -> None:
    from .code_watcher import watch

    watch(stop_event=stop_event)


def _health_reporter(stop_event: threading.Event) -> None:
    from .redis_client import get_client

    while not stop_event.wait(60):
        try:
            used = get_client().info("memory").get("used_memory_human", "?")
            logger.info("Health | redis_memory=%s status=running", used)
        except Exception as exc:
            logger.warning(
                "Health check failed | error_type=%s",
                type(exc).__name__,
            )


async def _run_api_watcher(
    controller: _ShutdownController,
    stop_event: asyncio.Event,
) -> None:
    try:
        from .api_watcher import watch

        await watch(stop_event=stop_event)
    except asyncio.CancelledError:
        raise
    except BaseException as exc:
        controller.fail("api-watcher", exc)


async def main() -> None:
    setup_logging(settings.log_level)
    settings.validate()
    wait_for_redis(timeout_secs=30.0)

    controller = _ShutdownController()
    async_stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    controller.bind_async(async_stop, loop)

    for watched_signal in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(
            watched_signal,
            controller.trigger,
            signal.Signals(watched_signal).name,
        )

    workers = (
        ("correlator", _run_correlator),
        ("code-watcher", _run_code_watcher),
        ("health", _health_reporter),
    )
    threads: List[threading.Thread] = []
    for component, target in workers:
        thread = threading.Thread(
            target=_thread_runner,
            args=(controller, component, target),
            name=component,
            daemon=False,
        )
        thread.start()
        threads.append(thread)
        logger.info("Component started | component=%s", component)

    api_task = asyncio.create_task(
        _run_api_watcher(controller, async_stop),
        name="api-watcher",
    )
    logger.info(
        "Security Watchtower started | env=%s platform=%s targets=%d",
        settings.env,
        settings.platform,
        len(settings.api_watcher.target_urls),
    )

    await async_stop.wait()
    controller.stop_event.set()
    if not api_task.done():
        api_task.cancel()
    try:
        await asyncio.wait_for(api_task, timeout=5.0)
    except (asyncio.CancelledError, asyncio.TimeoutError):
        pass

    for thread in threads:
        thread.join(timeout=10.0)
        if thread.is_alive():
            logger.error(
                "Component did not stop before timeout | component=%s",
                thread.name,
            )

    failure = controller.failure
    if failure:
        component, error_type = failure
        raise RuntimeError(
            f"Watchtower stopped after {component} failed with {error_type}"
        )
    logger.info("Security Watchtower shutdown complete")


if __name__ == "__main__":
    asyncio.run(main())
