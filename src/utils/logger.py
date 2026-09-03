"""Structured logging utility."""
import logging
import sys
import io
import os


def get_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    """Create or retrieve a logger with console handler (UTF-8 safe)."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        # Force UTF-8 on Windows
        if sys.platform == "win32":
            if hasattr(sys.stdout, "reconfigure"):
                try:
                    sys.stdout.reconfigure(encoding="utf-8")
                except Exception:
                    pass
            os.environ.setdefault("PYTHONIOENCODING", "utf-8")

        # Create a UTF-8 stream handler that works on all platforms
        try:
            stream = io.TextIOWrapper(
                sys.stdout.buffer, encoding="utf-8", errors="replace"
            )
        except Exception:
            stream = sys.stdout

        handler = logging.StreamHandler(stream)
        fmt = logging.Formatter(
            "[%(asctime)s] %(levelname)-8s %(name)s | %(message)s",
            datefmt="%H:%M:%S",
        )
        handler.setFormatter(fmt)
        logger.addHandler(handler)
    logger.setLevel(level)
    return logger
