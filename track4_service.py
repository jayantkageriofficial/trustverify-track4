"""Track 4 adapter v1 entry point: one JSON request on stdin, one JSON reply on stdout.

Needs only Python 3.12 and pqcrypto==0.4.0. The application logic lives in
trustverify/adapter.py. Diagnostics go to stderr and never include request
values, protected content, keys or the synthetic key material.

Every request ends with exit status 0 and exactly one JSON object. A request that
cannot be processed (malformed input, failed integrity check) gets a fail-closed
reply: ``{"decision":"deny","error":...}`` for reads, ``{"ready":false,...}`` for setup.
"""

import json
import sys

from trustverify.adapter import RequestError, dispatch, error_reply, record_malformed

MAX_REQUEST_BYTES = 64 * 1024 * 1024


def main():
    request = None
    try:
        raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
        if len(raw) > MAX_REQUEST_BYTES:
            raise RequestError("request too large")
        try:
            request = json.loads(raw.decode("utf-8"), parse_constant=_reject_constant)
        except (UnicodeDecodeError, ValueError, RecursionError):
            raise RequestError("request must be one UTF-8 JSON object") from None
        response = dispatch(request)
    except RequestError as error:
        # RequestError messages are fixed strings that never quote request data.
        print(f"trustverify adapter: {error}", file=sys.stderr)
        record_malformed(request)
        response = error_reply(request, str(error))
    except Exception as error:  # noqa: BLE001 - never echo details that could hold secrets
        print(f"trustverify adapter: internal error ({type(error).__name__})", file=sys.stderr)
        response = error_reply(request, "internal error")
    sys.stdout.write(json.dumps(response, allow_nan=False, separators=(",", ":")) + "\n")
    return 0


def _reject_constant(name):
    raise ValueError("non-finite number")


if __name__ == "__main__":
    raise SystemExit(main())
