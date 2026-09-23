"""Force control/payload ordering without relying on scheduler timing."""
import os
import socket
import threading
import unittest

from syq import StreamDestination, StreamSource
from syq._callback_io import TransferState
from syq._callback_runtime import Callbacks


class CallbackCompletionTests(unittest.TestCase):
    def invoke(self, endpoint, state, *, payload_closed=False):
        callbacks = Callbacks({}, 1)
        self.addCleanup(callbacks.close, abort=False)
        read, write = os.pipe()
        writer = isinstance(endpoint, StreamSource)
        payload, peer = (write, read) if writer else (read, write)
        if payload_closed:
            os.close(peer)
        else:
            self.addCleanup(os.close, peer)
        native, commit = socket.socketpair()
        native.close()
        thread = threading.Thread(target=callbacks._invoke,
            args=(endpoint, state, payload, commit.detach()), daemon=True)
        thread.start()
        return callbacks, thread

    def finish(self, callbacks, thread):
        thread.join(2)
        self.assertFalse(thread.is_alive(), "callback did not finish")
        callbacks.raise_error()

    def test_rejected_commit_waits_for_native_failure(self):
        for direction in ('produce', 'consume'):
            for early in (False, True):
                with self.subTest(direction=direction, early=early):
                    state = TransferState()
                    waiting = threading.Event()
                    wait = state.wait
                    def observed_wait():
                        waiting.set()
                        wait()
                    state.wait = observed_wait
                    if early or direction == 'consume':
                        state.settle('native validation failed' if early else None)
                    endpoint = (StreamSource(lambda out: out.write(b'data')) if direction == 'produce'
                                else StreamDestination(lambda source: None))
                    callbacks, thread = self.invoke(endpoint, state, payload_closed=direction == 'consume')
                    self.assertTrue(waiting.wait(2))
                    if not early and direction == 'produce':
                        self.assertTrue(thread.is_alive())
                        state.settle('native validation failed')
                    if direction == 'consume' and not early:
                        with self.assertRaises(BrokenPipeError):
                            self.finish(callbacks, thread)
                    else:
                        self.finish(callbacks, thread)

    def test_payload_broken_pipe_waits_for_native_failure(self):
        state = TransferState()
        waiting = threading.Event()
        wait = state.wait
        def observed_wait():
            waiting.set()
            wait()
        state.wait = observed_wait
        callbacks, thread = self.invoke(StreamSource(lambda out: out.write(b'data')), state,
                                        payload_closed=True)
        self.assertTrue(waiting.wait(2))
        state.settle('native validation failed')
        self.finish(callbacks, thread)

    def test_unexplained_commit_failure_remains_visible(self):
        state = TransferState()
        state.settle(None)
        callbacks, thread = self.invoke(StreamSource(lambda out: None), state)
        with self.assertRaises(BrokenPipeError):
            self.finish(callbacks, thread)

    def test_user_broken_pipe_is_not_swallowed(self):
        state = TransferState()
        state.settle('native validation failed')
        def produce(out):
            raise BrokenPipeError('application failure')
        callbacks, thread = self.invoke(StreamSource(produce), state)
        with self.assertRaisesRegex(BrokenPipeError, 'application failure'):
            self.finish(callbacks, thread)


class PayloadLifetimeTests(unittest.IsolatedAsyncioTestCase):
    async def test_cancelled_io_cannot_close_or_reuse_its_descriptor(self):
        import asyncio
        import io
        from syq._callback_io import AsyncPayload, Reader
        from syq._payload_io import OwnedPayload

        entered, release, closed = threading.Event(), threading.Event(), threading.Event()
        raw = io.BytesIO(b'payload')
        class PausedRead:
            def read(self, size=-1):
                entered.set()
                if not release.wait(3):
                    raise TimeoutError('test did not release payload read')
                return raw.read(size)
            def close(self):
                closed.set()
                raw.close()
            @property
            def closed(self):
                return raw.closed
            def flush(self):
                raw.flush()

        payload = OwnedPayload(PausedRead())
        state = TransferState()
        state.settle(None)
        task = asyncio.create_task(AsyncPayload(Reader(payload, state)).read())
        self.assertTrue(await asyncio.to_thread(entered.wait, 2))
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        closing = threading.Thread(target=payload.close, daemon=True)
        closing.start()
        try:
            self.assertFalse(await asyncio.to_thread(closed.wait, .05),
                             'payload closed while background I/O was still active')
        finally:
            release.set()
            await asyncio.to_thread(closing.join, 2)
        self.assertFalse(closing.is_alive())
        self.assertTrue(closed.is_set())
        with self.assertRaises(ValueError):
            payload.read()
