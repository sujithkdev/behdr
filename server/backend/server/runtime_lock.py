"""OS-held lock released automatically if the server exits or crashes."""
import os
from contextlib import contextmanager


@contextmanager
def exclusive_instance(path):
    handle = open(path, "a+b")
    try:
        handle.seek(0)
        if os.name == "nt":
            import msvcrt
            if not handle.read(1):
                handle.write(b"0")
                handle.flush()
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        handle.close()
        raise RuntimeError("Another server owns this data directory") from exc
    try:
        yield
    finally:
        handle.close()
