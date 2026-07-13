"""
Safe ZIP project extraction.

Guards against zip-slip (path traversal via crafted zip entry names) and
zip bombs (excessive uncompressed size / file count) since a security
scanner is itself a juicy target for malicious uploads.
"""

import os
import zipfile

MAX_FILES = 500
MAX_TOTAL_UNCOMPRESSED_BYTES = 50 * 1024 * 1024  # 50 MB
SCANNABLE_EXTENSIONS = {'.py', '.js', '.jsx', '.ts', '.tsx', '.html', '.htm', '.css'}
SKIP_DIR_NAMES = {'node_modules', '.git', '__pycache__', 'venv', '.venv', 'dist', 'build'}


class ZipSecurityError(Exception):
    pass


def extract_scannable_files(zip_file) -> list[dict]:
    """
    Given a Django UploadedFile (in-memory or temp-file zip), return a list of
    {"filename": str, "content": str} dicts for every scannable source file,
    without ever writing extracted files to disk unsanitized.
    """
    results = []
    total_size = 0

    with zipfile.ZipFile(zip_file) as archive:
        infolist = archive.infolist()
        if len(infolist) > MAX_FILES:
            raise ZipSecurityError(f'ZIP contains too many files (max {MAX_FILES}).')

        for info in infolist:
            # zip-slip guard: reject any entry that would escape the extraction root
            normalized = os.path.normpath(info.filename)
            if normalized.startswith('..') or os.path.isabs(normalized):
                raise ZipSecurityError(f'Unsafe path detected in ZIP: {info.filename}')

            if info.is_dir():
                continue

            if any(skip in normalized.split(os.sep) for skip in SKIP_DIR_NAMES):
                continue

            total_size += info.file_size
            if total_size > MAX_TOTAL_UNCOMPRESSED_BYTES:
                raise ZipSecurityError('ZIP uncompressed size exceeds the allowed limit.')

            ext = os.path.splitext(normalized)[1].lower()
            if ext not in SCANNABLE_EXTENSIONS:
                continue

            try:
                with archive.open(info) as f:
                    raw = f.read(2 * 1024 * 1024)  # cap per-file read at 2MB
                    content = raw.decode('utf-8', errors='ignore')
            except (UnicodeDecodeError, RuntimeError):
                continue

            results.append({'filename': normalized, 'content': content})

    return results
