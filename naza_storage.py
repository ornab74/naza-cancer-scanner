"""Durable private writes and recoverable encrypted-file replacement (POSIX).

Call recovery before opening the key or data. The caller supplies the fixed
allowed target list; recovery never follows paths supplied by a journal.
"""
import contextlib
import fcntl
import json
import os
from pathlib import Path
import secrets
import shutil
import stat


def private_directory(path):
    path = Path(path)
    st = os.stat(str(path), follow_symlinks=False)
    if not stat.S_ISDIR(st.st_mode):
        raise ValueError(f'Refusing non-directory storage root: {path}')
    if st.st_uid != os.geteuid():
        raise PermissionError(f'Storage directory is owned by another user: {path}')
    if st.st_mode & 0o022:
        raise PermissionError(f'Storage directory is group/other writable: {path}')


def sync_dir(path):
    fd = os.open(str(path), os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def regular(path):
    try:
        mode = os.lstat(str(path)).st_mode
    except FileNotFoundError:
        return
    if not stat.S_ISREG(mode):
        raise ValueError(f'Refusing non-regular file: {path}')


def read_regular(path, maximum=None):
    """Read a regular file without following its final path component."""
    path = Path(path)
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(f'Refusing non-regular file: {path}')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read() if maximum is None else stream.read(maximum + 1)
        if maximum is not None and len(data) > maximum:
            raise ValueError(f'File exceeds maximum size: {path}')
        return data
    finally:
        os.close(fd)


def read_private(path, maximum=None):
    """Read a current-user-owned regular file with no group/other access."""
    path = Path(path)
    st = os.stat(str(path), follow_symlinks=False)
    if st.st_uid != os.geteuid():
        raise PermissionError(f'File is owned by another user: {path}')
    if st.st_mode & 0o077:
        raise PermissionError(f'File is readable or writable by group/other: {path}')
    return read_regular(path, maximum)


def atomic_write(path, data):
    path = Path(path)
    private_directory(path.parent)
    regular(path)
    tmp = path.with_name(path.name + '.' + secrets.token_hex(8) + '.tmp')
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        sync_dir(path.parent)
    finally:
        if tmp.exists():
            tmp.unlink()


@contextlib.contextmanager
def _locked(root):
    root = Path(root)
    private_directory(root)
    lock = root / '.naza-rotation.lock'
    fd = os.open(str(lock), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(f'Refusing non-regular lock file: {lock}')
        if st.st_uid != os.geteuid():
            raise PermissionError(f'Lock file is owned by another user: {lock}')
        if st.st_mode & 0o077:
            raise PermissionError(f'Lock file has unsafe permissions: {lock}')
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield root / '.naza-rotation'
    finally:
        os.close(fd)


def _cleanup(journal):
    shutil.rmtree(journal)
    sync_dir(journal.parent)


def _recover(journal, targets):
    if journal.is_symlink():
        raise ValueError('Refusing symlink rotation journal')
    if not journal.exists():
        return False
    manifest = journal / 'manifest.json'
    regular(manifest)
    if not manifest.exists():
        # Preparation did not finish; no live files were replaced.
        _cleanup(journal)
        return False
    record = json.loads(read_regular(manifest, 64 * 1024))
    expected = [str(Path(p).absolute()) for p in targets]
    if (record.get('version') != 1 or record.get('targets') != expected
            or type(record.get('committed')) is not bool
            or not isinstance(record.get('existed'), list)
            or len(record['existed']) != len(targets)
            or any(type(v) is not bool for v in record['existed'])):
        raise ValueError('Invalid rotation journal; recovery stopped')
    if not record['committed']:
        # Check all backups before restoring any target.
        for i, existed in enumerate(record['existed']):
            regular(Path(targets[i]))
            if existed:
                backup = journal / f'{i}.old'
                regular(backup)
                if not backup.is_file():
                    raise ValueError('Incomplete rotation backup')
        for i, existed in enumerate(record['existed']):
            path = Path(targets[i])
            if existed:
                atomic_write(path, read_regular(journal / f'{i}.old'))
            elif path.exists():
                path.unlink()
                sync_dir(path.parent)
    rolled_back = not record['committed']
    if rolled_back:
        record['committed'] = True
        atomic_write(manifest, json.dumps(record).encode())
    _cleanup(journal)
    return rolled_back


def recover(root, targets):
    with _locked(root) as journal:
        return _recover(journal, targets)


def replace_batch(root, targets, prepare):
    """Stage prepare()'s bytes in target order, then replace as a recoverable batch.

    prepare must authenticate/verify every new encrypted artifact before yielding.
    Backups and staged files contain encrypted data only. An unfinished commit is
    rolled back on error or by recover() after process interruption.
    """
    targets = [Path(p) for p in targets]
    if len(set(p.absolute() for p in targets)) != len(targets):
        raise ValueError('Duplicate rotation targets')
    with _locked(root) as journal:
        _recover(journal, targets)
        journal.mkdir(mode=0o700)
        sync_dir(journal.parent)
        try:
            existed = []
            for i, path in enumerate(targets):
                regular(path)
                existed.append(path.exists())
                if path.exists():
                    atomic_write(journal / f'{i}.old', read_regular(path))
            count = 0
            for i, blob in enumerate(prepare()):
                if i >= len(targets):
                    raise ValueError('Too many staged files')
                if blob is not None:
                    atomic_write(journal / f'{i}.new', blob)
                count += 1
            if count != len(targets):
                raise ValueError('Missing staged files')
            record = dict(version=1, targets=[str(p.absolute()) for p in targets], existed=existed, committed=False)
            atomic_write(journal / 'manifest.json', json.dumps(record).encode())
            for i, path in enumerate(targets):
                staged = journal / f'{i}.new'
                if staged.exists():
                    atomic_write(path, read_regular(staged))
                elif path.exists():
                    path.unlink()
                    sync_dir(path.parent)
            record['committed'] = True
            atomic_write(journal / 'manifest.json', json.dumps(record).encode())
        except BaseException:
            # A write may raise after replacement (for example directory fsync).
            # If the commit marker is already visible, keep the complete new set
            # and report success so the caller switches to its new in-memory key.
            manifest = journal / 'manifest.json'
            committed = manifest.exists() and json.loads(read_regular(manifest, 64 * 1024)).get('committed') is True
            _recover(journal, targets)
            if not committed:
                raise
        # Cleanup is recoverable too; a committed marker preserves the new set.
        try:
            _cleanup(journal)
        except OSError:
            pass
