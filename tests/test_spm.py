#!/usr/bin/env python3
"""End-to-end functional, security, signal, and memory tests for spm."""

import fcntl
import os
import pty
import re
import resource
import select
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import termios
import time

SPM = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "./spm")
MASTER_PW = "S3CR3T_MASTER_1!"
LOG_RE = re.compile(
    r"^ts=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z uid=\d+ pid=\d+ "
    r"event=[A-Za-z0-9_-]+ outcome=[A-Za-z0-9_-]+ detail=[A-Za-z0-9_-]+$"
)


def echo_on(fd):
    return bool(termios.tcgetattr(fd)[3] & termios.ECHO)


def spawn_pty(cwd, args=None, env=None, preexec_extra=None):
    if args is None:
        args = []
    m, s = pty.openpty()

    def preexec():
        os.setsid()
        fcntl.ioctl(s, termios.TIOCSCTTY, 0)
        if preexec_extra:
            preexec_extra()

    p = subprocess.Popen(
        [SPM] + args,
        cwd=cwd,
        stdin=s,
        stdout=s,
        stderr=s,
        preexec_fn=preexec,
        close_fds=True,
        env=env,
    )
    os.close(s)
    return p, m


def read_until(m, needle, timeout=6.0):
    buf = b""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        r, _, _ = select.select([m], [], [], 0.1)
        if m in r:
            try:
                chunk = os.read(m, 4096)
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
            if needle in buf:
                return buf
    raise AssertionError(f"Timeout waiting for {needle!r}; got {buf!r}")


def wait_tty(p, m):
    out = b""
    rc = p.wait(timeout=6)
    while True:
        r, _, _ = select.select([m], [], [], 0.05)
        if not r:
            break
        try:
            c = os.read(m, 4096)
            if not c:
                break
            out += c
        except OSError:
            break
    echo = echo_on(m)
    os.close(m)
    return rc, out, echo


def test_missing_vault_and_help(tmp):
    d_empty = os.path.join(tmp, "empty")
    os.makedirs(d_empty)

    r = subprocess.run([SPM, "--help"], cwd=d_empty, text=True, capture_output=True)
    assert r.returncode == 0 and "Usage:" in r.stdout and "del-vault" in r.stdout
    assert not os.path.exists(os.path.join(d_empty, "spm.log"))

    for cmd in (["list"], ["add", "git"], ["get", "git"], ["del", "git"], ["del-vault"]):
        r = subprocess.run([SPM] + cmd, cwd=d_empty, text=True, capture_output=True)
        assert r.returncode == 1
        assert "No vault found. Run 'init' first." in r.stderr
        assert "Master password:" not in r.stdout

    # Broken symlink must still fail generically instead of exposing no_vault
    d_sym = os.path.join(tmp, "broken_sym")
    os.makedirs(d_sym)
    os.symlink("/nonexistent_target_xyz", os.path.join(d_sym, "vault.bin"))
    r = subprocess.run([SPM, "list"], cwd=d_sym, input=MASTER_PW + "\n", text=True, capture_output=True)
    assert r.returncode == 1 and "Could not unlock the vault." in r.stderr

    # One-shot CLI bad syntax / arg counts
    for bad_args in (["badcmd"], ["init", "extra"], ["list", "extra"], ["del-vault", "extra"], ["add"]):
        rc = subprocess.run([SPM] + bad_args, cwd=d_empty, text=True, capture_output=True)
        assert rc.returncode == 1 and "Usage:" in rc.stdout, (bad_args, rc)

    # make clean must remove build outputs while keeping vault.bin and spm.log
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    mk_dir = os.path.join(tmp, "mk_clean")
    os.makedirs(mk_dir)
    shutil.copy2(os.path.join(repo_root, "Makefile"), os.path.join(mk_dir, "Makefile"))
    os.makedirs(os.path.join(mk_dir, "obj"))
    open(os.path.join(mk_dir, "obj", "main.o"), "wb").write(b"o")
    open(os.path.join(mk_dir, "spm"), "wb").write(b"b")
    open(os.path.join(mk_dir, "spm_asan"), "wb").write(b"a")
    open(os.path.join(mk_dir, "vault.bin"), "wb").write(b"v")
    open(os.path.join(mk_dir, "spm.log"), "wb").write(b"l")
    assert subprocess.run(["make", "clean"], cwd=mk_dir, check=True, capture_output=True).returncode == 0
    assert os.path.exists(os.path.join(mk_dir, "vault.bin")) and os.path.exists(os.path.join(mk_dir, "spm.log"))
    assert not os.path.exists(os.path.join(mk_dir, "obj"))
    assert not os.path.exists(os.path.join(mk_dir, "spm")) and not os.path.exists(os.path.join(mk_dir, "spm_asan"))
    print("[PASS] help, CLI syntax, missing-vault, broken-symlink, and make clean")


def test_init_and_validation(tmp):
    d = os.path.join(tmp, "init_val")
    os.makedirs(d)

    p, m = spawn_pty(d)
    read_until(m, b"spm> ")
    os.write(m, b"help\n")
    hout = read_until(m, b"spm> ")
    assert b"Commands:\r\n  init" in hout and b"del-vault" in hout and b"exit | quit" in hout

    os.write(m, b"init\n")
    read_until(m, b"Master password: ")
    os.write(m, b"short7!\n")
    assert b"Master password must be 8 to 126 normal characters." in read_until(m, b"spm> ")

    os.write(m, b"init\n")
    read_until(m, b"Master password: ")
    os.write(m, b"bad\x1b[Akey1\n")
    assert b"Master password must be 8 to 126 normal characters." in read_until(m, b"spm> ")

    os.write(m, b"init\n")
    read_until(m, b"Master password: ")
    os.write(m, b"O" * 127 + b"\n")
    assert b"Master password must be 8 to 126 normal characters." in read_until(m, b"spm> ")

    os.write(m, b"init\n")
    read_until(m, b"Master password: ")
    os.write(m, MASTER_PW.encode() + b"\n")
    read_until(m, b"Confirm master password: ")
    os.write(m, b"MismatchPass1!\n")
    assert b"Master passwords do not match." in read_until(m, b"spm> ")
    assert not os.path.exists(os.path.join(d, "vault.bin"))

    # Valid init with Ctrl+C -> n mid-confirmation
    os.write(m, b"init\n")
    read_until(m, b"Master password: ")
    os.write(m, MASTER_PW.encode() + b"\n")
    read_until(m, b"Confirm master password: ")
    os.write(m, b"half\x03")
    read_until(m, b"Exit cleanly? [y/N]: ")
    os.write(m, b"n\n")
    read_until(m, b"Confirm master password: ")
    os.write(m, MASTER_PW.encode() + b"\n")
    assert b"Vault created." in read_until(m, b"spm> ")

    # Strict service/username/password allowlists
    for bad_svc in (b"add .\n", b"add ..\n", b"add a..b\n", b"add a/b\n", b"add a;ls\n", b"add a|b\n", b"add " + b"x" * 64 + b"\n"):
        os.write(m, bad_svc)
        assert b"Commands:" in read_until(m, b"spm> "), bad_svc

    os.write(m, b"add github.com\n")
    read_until(m, b"Username: ")
    os.write(m, b"bad user\n")
    assert b"Invalid username" in read_until(m, b"spm> ")

    os.write(m, b"add github.com\n")
    read_until(m, b"Username: ")
    os.write(m, b"alice+dev@ex.org\n")
    read_until(m, b"Password: ")
    os.write(m, b"bad\x1bpass\n")
    assert b"Invalid entry password." in read_until(m, b"spm> ")

    # Re-init when vault exists must fail cleanly without altering vault.bin
    orig_v = open(os.path.join(d, "vault.bin"), "rb").read()
    os.write(m, b"init\n")
    assert b"A vault already exists." in read_until(m, b"spm> ")
    assert open(os.path.join(d, "vault.bin"), "rb").read() == orig_v

    # exit with extra arg must NOT exit; leading/trailing spaces work; line/user/pass overflow drains cleanly
    os.write(m, b"exit extra\n")
    assert b"Commands:" in read_until(m, b"spm> ")
    os.write(m, b"   list   \n")
    assert b"Vault is empty." in read_until(m, b"spm> ")
    os.write(m, b"A" * 260 + b"\n")
    assert b"Invalid command input." in read_until(m, b"spm> ")
    os.write(m, b"help\n")
    assert b"Commands:" in read_until(m, b"spm> ")

    os.write(m, b"add github.com\n")
    read_until(m, b"Username: ")
    os.write(m, b"u" * 64 + b"\n")
    assert b"Invalid username" in read_until(m, b"spm> ")
    os.write(m, b"help\n")
    assert b"Commands:" in read_until(m, b"spm> ")

    os.write(m, b"add github.com\n")
    read_until(m, b"Username: ")
    os.write(m, b"alice\n")
    read_until(m, b"Password: ")
    os.write(m, b"p" * 128 + b"\n")
    assert b"Invalid entry password." in read_until(m, b"spm> ")
    os.write(m, b"help\n")
    assert b"Commands:" in read_until(m, b"spm> ")

    # Exact max boundary lengths: 63-char service/username, 126-char password with spaces & %s%n format string literal
    max_svc = "S" * 63
    max_usr = "U" * 63
    max_epw = ("my pass %s%n " * 10)[:126]
    os.write(m, f"add {max_svc}\n".encode())
    read_until(m, b"Username: ")
    os.write(m, max_usr.encode() + b"\n")
    read_until(m, b"Password: ")
    os.write(m, max_epw.encode() + b"\n")
    assert b"Entry saved." in read_until(m, b"spm> ")

    # 1-char password & %s%n literal username/service characters (+ valid_ident allowed punctuation)
    os.write(m, b"add a._-@+1\n")
    read_until(m, b"Username: ")
    os.write(m, b"u._-@+2\n")
    read_until(m, b"Password: ")
    os.write(m, b"1\n")
    assert b"Entry saved." in read_until(m, b"spm> ")
    os.write(m, b"list\n")
    lout = read_until(m, b"spm> ")
    assert max_svc.encode() in lout and max_usr.encode() in lout and b"a._-@+1 (user: u._-@+2)" in lout

    os.write(m, b"exit\n")
    rc, _, echo = wait_tty(p, m)
    assert rc == 0 and echo

    # Embedded NUL before newline must fail without eating the next input line
    r_nul = subprocess.run(
        [SPM],
        cwd=d,
        input=b"list\n" + MASTER_PW.encode() + b"\nadd nul.org\nbob\nbad\x00pw\nlist\nexit\n",
        capture_output=True,
    )
    assert r_nul.returncode == 0
    assert b"Invalid entry password." in r_nul.stderr
    assert b"a._-@+1 (user: u._-@+2)" in r_nul.stdout

    # Embedded NUL before EOF with no trailing newline must also be rejected cleanly
    r_nul_eof = subprocess.run(
        [SPM, "list"],
        cwd=d,
        input=MASTER_PW[:4].encode() + b"\x00" + MASTER_PW[4:].encode(),
        capture_output=True,
    )
    assert r_nul_eof.returncode == 1 and b"Unlock cancelled." in r_nul_eof.stderr
    assert b"Could not unlock" not in r_nul_eof.stderr
    assert open(os.path.join(d, "vault.bin"), "rb").read()[5] == 0

    r_add_nul_eof = subprocess.run(
        [SPM, "add", "nuleof.org"],
        cwd=d,
        input=MASTER_PW.encode() + b"\nbob\npw\x00extra",
        capture_output=True,
    )
    assert r_add_nul_eof.returncode == 1 and b"Invalid entry password." in r_add_nul_eof.stderr

    # Exact 126-char max master password init + unlock check
    d_max = os.path.join(tmp, "max_master")
    os.makedirs(d_max)
    max_mpw = "M" * 126
    assert subprocess.run([SPM, "init"], cwd=d_max, input=f"{max_mpw}\n{max_mpw}\n", text=True, capture_output=True).returncode == 0
    assert subprocess.run([SPM, "list"], cwd=d_max, input=f"{max_mpw}\n", text=True, capture_output=True).returncode == 0

    # TOCTOU O_EXCL check: vault created during confirm prompt must not be overwritten
    d_race = os.path.join(tmp, "race")
    os.makedirs(d_race)
    p, m = spawn_pty(d_race)
    read_until(m, b"spm> ")
    os.write(m, b"init\n")
    read_until(m, b"Master password: ")
    os.write(m, MASTER_PW.encode() + b"\n")
    read_until(m, b"Confirm master password: ")
    with open(os.path.join(d_race, "vault.bin"), "wb") as f:
        f.write(b"EXISTING_VAULT")
    os.chmod(os.path.join(d_race, "vault.bin"), 0o600)
    os.write(m, MASTER_PW.encode() + b"\n")
    assert b"Could not create the vault." in read_until(m, b"spm> ")
    assert open(os.path.join(d_race, "vault.bin"), "rb").read() == b"EXISTING_VAULT"
    os.write(m, b"exit\n")
    assert wait_tty(p, m)[0] == 0
    print("[PASS] init confirmation, bounds, allowlists, and TOCTOU O_EXCL race guard")


def test_crud_clipboard_and_capacity(tmp):
    d = os.path.join(tmp, "crud")
    os.makedirs(d)
    mockbin = os.path.join(tmp, "mockbin")
    os.makedirs(mockbin)
    cap = os.path.join(tmp, "clip.txt")
    clip_args = os.path.join(tmp, "clip_args.txt")
    wl = os.path.join(mockbin, "wl-copy")
    with open(wl, "w", encoding="utf-8") as f:
        f.write(f"#!/bin/sh\nprintf '%s\\n' \"$*\" >> {clip_args}\ncat > {cap}\n")
    os.chmod(wl, 0o755)
    env_mock = dict(os.environ)
    env_mock["PATH"] = mockbin + ":/usr/bin:/bin"
    env_mock["SPM_CLIP_TIMEOUT"] = "1"

    p, m = spawn_pty(d, env=env_mock)
    read_until(m, b"spm> ")
    os.write(m, b"init\n")
    read_until(m, b"Master password: ")
    os.write(m, MASTER_PW.encode() + b"\n")
    read_until(m, b"Confirm master password: ")
    os.write(m, MASTER_PW.encode() + b"\n")
    assert b"Vault created." in read_until(m, b"spm> ")

    # Fill all 50 entries and verify zero plaintext password echoes
    for i in range(50):
        os.write(m, f"add svc{i}.org\n".encode())
        read_until(m, b"Username: ")
        os.write(m, f"usr+{i}@ex.org\n".encode())
        read_until(m, b"Password: ")
        sec = f"EntrySecret_{i}!".encode()
        os.write(m, sec + b"\n")
        out = read_until(m, b"spm> ")
        assert sec not in out and b"Entry saved." in out

    os.write(m, b"add svc50.org\n")
    assert b"Vault is full." in read_until(m, b"spm> ")

    # Updating existing entry succeeds even at full capacity
    os.write(m, b"add svc0.org\n")
    read_until(m, b"Username: ")
    os.write(m, b"upd@ex.org\n")
    read_until(m, b"Password: ")
    os.write(m, b"UpdatedSecret_0!\n")
    assert b"Entry saved." in read_until(m, b"spm> ")

    # get copies secret, prints lifetime, and timer automatically runs --clear after TTL
    os.write(m, b"get svc0.org\n")
    out = read_until(m, b"spm> ")
    assert b"svc0.org (user: upd@ex.org)" in out
    assert b"svc0.org (pass: in clipboard)" in out
    assert b"Clipboard clears in 1 second(s)." in out
    assert open(cap, "r", encoding="utf-8").read() == "UpdatedSecret_0!"
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        if open(cap, "r", encoding="utf-8").read() == "":
            break
        time.sleep(0.1)
    assert open(cap, "r", encoding="utf-8").read() == ""
    assert open(clip_args, "r", encoding="utf-8").read().splitlines() == ["", "--clear"]

    # Delete all 50 entries down to empty vault
    for i in range(50):
        os.write(m, f"del svc{i}.org\n".encode())
        assert b"Entry deleted." in read_until(m, b"spm> ")
    os.write(m, b"list\n")
    assert b"Vault is empty." in read_until(m, b"spm> ")
    os.write(m, b"quit\n")
    rc, _, echo = wait_tty(p, m)
    assert rc == 0 and echo
    assert os.path.getsize(os.path.join(d, "vault.bin")) == 64

    # Relative '.' in PATH must be ignored; non-zero helper exit must fail cleanly
    with open(wl, "w", encoding="utf-8") as f:
        f.write("#!/bin/sh\nexit 1\n")
    d_clip = os.path.join(tmp, "clipneg")
    os.makedirs(d_clip)
    assert subprocess.run([SPM, "init"], cwd=d_clip, input=f"{MASTER_PW}\n{MASTER_PW}\n", text=True, capture_output=True).returncode == 0
    assert subprocess.run([SPM, "add", "git"], cwd=d_clip, input=f"{MASTER_PW}\nroot\npw1\n", text=True, capture_output=True).returncode == 0
    r = subprocess.run([SPM, "get", "git"], cwd=d_clip, input=MASTER_PW + "\n", text=True, capture_output=True, env=env_mock)
    assert r.returncode == 1 and "Could not copy to clipboard." in r.stderr
    os.symlink(wl, os.path.join(d_clip, "wl-copy"))
    env_rel = dict(os.environ)
    env_rel["PATH"] = ".:/nope"
    r = subprocess.run([SPM, "get", "git"], cwd=d_clip, input=MASTER_PW + "\n", text=True, capture_output=True, env=env_rel)
    assert r.returncode == 1 and "Could not copy to clipboard." in r.stderr
    assert subprocess.run([SPM, "get", "missing"], cwd=d_clip, input=MASTER_PW + "\n", text=True, capture_output=True).returncode == 1
    assert subprocess.run([SPM, "del", "missing"], cwd=d_clip, input=MASTER_PW + "\n", text=True, capture_output=True).returncode == 1
    assert subprocess.run([SPM, "add", "srv2"], cwd=d_clip, input=f"{MASTER_PW}\nbob\npw2\n", text=True, capture_output=True).returncode == 0
    assert subprocess.run([SPM, "del", "srv2"], cwd=d_clip, input=MASTER_PW + "\n", text=True, capture_output=True).returncode == 0
    assert not any(fn.startswith("vault.bin.") for fn in os.listdir(d))
    assert not any(fn.startswith("vault.bin.") for fn in os.listdir(d_clip))
    print("[PASS] 50-entry CRUD stress, CLI add/del, mock clipboard get & PATH hardening")


def test_unlock_retry_and_wipe(tmp):
    d = os.path.join(tmp, "wipe")
    os.makedirs(d)
    vp = os.path.join(d, "vault.bin")
    assert subprocess.run([SPM, "init"], cwd=d, input=f"{MASTER_PW}\n{MASTER_PW}\n", text=True, capture_output=True).returncode == 0
    assert subprocess.run([SPM, "add", "git"], cwd=d, input=f"{MASTER_PW}\nroot\npw99\n", text=True, capture_output=True).returncode == 0

    # Empty, control byte, and EOF must not consume attempts
    for bad in ("", "\x1b[A\n", "\n"):
        subprocess.run([SPM, "list"], cwd=d, input=bad, text=True, capture_output=True)
    assert open(vp, "rb").read()[5] == 0

    # Interactive unlock retry: 2 wrong, blank, Ctrl+D cancel -> preserves fail_count=2, then retry + unlock resets to 0
    p, m = spawn_pty(d)
    read_until(m, b"spm> ")
    os.write(m, b"list\n")
    read_until(m, b"Master password: ")
    os.write(m, b"bad1\n")
    assert b"(9 attempts remaining)" in read_until(m, b"Master password: ")
    os.write(m, b"\n")
    assert b"Invalid password input." in read_until(m, b"Master password: ")
    os.write(m, b"bad2\n")
    assert b"(8 attempts remaining)" in read_until(m, b"Master password: ")
    os.write(m, b"\x04")
    assert b"Unlock cancelled." in read_until(m, b"spm> ")
    assert open(vp, "rb").read()[5] == 2

    os.write(m, b"list\n")
    read_until(m, b"Master password: ")
    for idx in range(3, 10):
        os.write(m, b"wrong\n")
        rem = 10 - idx
        unit = b"attempt" if rem == 1 else b"attempts"
        assert f"({rem} ".encode() + unit + b" remaining)" in read_until(m, b"Master password: ")
    os.write(m, MASTER_PW.encode() + b"\n")
    assert b"git (user: root)" in read_until(m, b"spm> ")
    assert open(vp, "rb").read()[5] == 0

    # Exit, then fail 10 consecutive times in single CLI command -> destroys vault.bin
    os.write(m, b"exit\n")
    assert wait_tty(p, m)[0] == 0

    p, m = spawn_pty(d, args=["list"])
    read_until(m, b"Master password: ")
    for _ in range(9):
        os.write(m, b"wrongpw\n")
        read_until(m, b"Master password: ")
    os.write(m, b"wrongpw\n")
    rc, tail, echo = wait_tty(p, m)
    assert rc == 1 and echo and b"Maximum failed attempts reached. Vault destroyed." in tail
    assert not os.path.exists(vp)

    # Pre-saturated fail_count=10 on disk gets cleaned up cleanly
    assert subprocess.run([SPM, "init"], cwd=d, input=f"{MASTER_PW}\n{MASTER_PW}\n", text=True, capture_output=True).returncode == 0
    raw = bytearray(open(vp, "rb").read())
    raw[5] = 10
    open(vp, "wb").write(raw)
    r = subprocess.run([SPM, "list"], cwd=d, input=MASTER_PW + "\n", text=True, capture_output=True)
    assert r.returncode == 1 and "Maximum failed attempts reached. Vault destroyed." in r.stderr
    assert not os.path.exists(vp)
    assert "event=UNLOCK outcome=FAIL detail=max_attempts_wiped" in open(os.path.join(d, "spm.log"), encoding="utf-8").read()
    print("[PASS] interactive unlock retry, counter reset after 9, and vault wipe at 10")


def test_aad_permissions_and_del_vault(tmp):
    d = os.path.join(tmp, "aad")
    os.makedirs(d)
    vp = os.path.join(d, "vault.bin")
    assert subprocess.run([SPM, "init"], cwd=d, input=f"{MASTER_PW}\n{MASTER_PW}\n", text=True, capture_output=True).returncode == 0
    assert subprocess.run([SPM, "add", "git"], cwd=d, input=f"{MASTER_PW}\nroot\nsecret\n", text=True, capture_output=True).returncode == 0

    orig = open(vp, "rb").read()
    # Non-counter header fields, salt, nonce, ciphertext, and tag tamper detection
    for idx in (0, 4, 6, 7, 8, 24, 48, len(orig) - 1):
        t = bytearray(orig)
        t[idx] ^= 0x01
        open(vp, "wb").write(t)
        r = subprocess.run([SPM, "list"], cwd=d, input=MASTER_PW + "\n", text=True, capture_output=True)
        assert r.returncode == 1
        open(vp, "wb").write(orig)

    # Truncation check
    open(vp, "wb").write(orig[:-1])
    assert subprocess.run([SPM, "list"], cwd=d, input=MASTER_PW + "\n", text=True, capture_output=True).returncode == 1
    open(vp, "wb").write(orig)

    # Permission check (0644 refused immediately without looping)
    os.chmod(vp, 0o644)
    p, m = spawn_pty(d, args=["list"])
    read_until(m, b"Master password: ")
    os.write(m, MASTER_PW.encode() + b"\n")
    rc, tail, echo = wait_tty(p, m)
    assert rc == 1 and echo and b"Could not unlock the vault." in tail
    os.chmod(vp, 0o600)

    # Post-unlock mid-session tampering: 0644 blocks add, del, and del-vault cleanly and preserves RAM entries
    p, m = spawn_pty(d)
    read_until(m, b"spm> ")
    os.write(m, b"list\n")
    read_until(m, b"Master password: ")
    os.write(m, MASTER_PW.encode() + b"\n")
    assert b"git (user: root)" in read_until(m, b"spm> ")

    os.chmod(vp, 0o644)
    os.write(m, b"add rolledback\n")
    read_until(m, b"Username: ")
    os.write(m, b"u\n")
    read_until(m, b"Password: ")
    os.write(m, b"pw\n")
    assert b"Could not save the vault." in read_until(m, b"spm> ")
    assert not any(fn.startswith("vault.bin.") for fn in os.listdir(d))

    os.write(m, b"del git\n")
    assert b"Could not save the vault." in read_until(m, b"spm> ")
    os.write(m, b"list\n")
    lbad = read_until(m, b"spm> ")
    assert b"Could not access the vault." in lbad and b"git (user: root)" not in lbad
    os.write(m, b"get git\n")
    gbad = read_until(m, b"spm> ")
    assert b"Could not access the vault." in gbad and b"in clipboard" not in gbad

    os.write(m, b"del-vault\n")
    read_until(m, b"Type YES to confirm: ")
    os.write(m, b"YES\n")
    assert b"Could not delete the vault." in read_until(m, b"spm> ")
    assert os.path.exists(vp)
    os.chmod(vp, 0o600)
    os.write(m, b"list\n")
    lout = read_until(m, b"spm> ")
    assert b"git (user: root)" in lout and b"rolledback" not in lout

    # del-vault cancel with 'yes', Ctrl+C abort, then YES delete + same-session re-init
    os.write(m, b"del-vault\n")
    read_until(m, b"Type YES to confirm: ")
    os.write(m, b"yes\n")
    assert b"Vault deletion cancelled." in read_until(m, b"spm> ")
    assert os.path.exists(vp)

    os.write(m, b"del-vault\n")
    read_until(m, b"Type YES to confirm: ")
    os.write(m, b"\x03")
    read_until(m, b"Exit cleanly? [y/N]: ")
    os.write(m, b"n\n")
    read_until(m, b"Type YES to confirm: ")
    os.write(m, b"no\n")
    assert b"Vault deletion cancelled." in read_until(m, b"spm> ")
    assert os.path.exists(vp)

    os.write(m, b"del-vault\n")
    read_until(m, b"Type YES to confirm: ")
    os.write(m, b"YES\n")
    assert b"Vault deleted." in read_until(m, b"spm> ")
    d_log_txt = open(os.path.join(d, "spm.log"), encoding="utf-8").read()
    assert "event=LIST outcome=FAIL detail=access_denied" in d_log_txt
    assert "event=GET outcome=FAIL detail=access_denied" in d_log_txt
    assert "event=DEL_VAULT outcome=FAIL detail=delete_failed" in d_log_txt
    assert "event=DEL_VAULT outcome=FAIL detail=cancelled" in d_log_txt
    assert "event=DEL_VAULT outcome=OK detail=vault_deleted" in d_log_txt
    assert not os.path.exists(vp)
    os.write(m, b"list\n")
    assert b"No vault found. Run 'init' first." in read_until(m, b"spm> ")
    os.write(m, b"init\n")
    read_until(m, b"Master password: ")
    os.write(m, MASTER_PW.encode() + b"\n")
    read_until(m, b"Confirm master password: ")
    os.write(m, MASTER_PW.encode() + b"\n")
    assert b"Vault created." in read_until(m, b"spm> ")
    os.write(m, b"exit\n")
    assert wait_tty(p, m)[0] == 0

    # FIFO on vault.bin refused without hanging
    d_fifo = os.path.join(tmp, "vfifo")
    os.makedirs(d_fifo)
    os.mkfifo(os.path.join(d_fifo, "vault.bin"))
    r = subprocess.run([SPM, "list"], cwd=d_fifo, input=MASTER_PW + "\n", text=True, capture_output=True, timeout=5)
    assert r.returncode == 1 and "Could not unlock the vault." in r.stderr
    print("[PASS] AAD tampering, 0644/FIFO checks, and del-vault")


def test_signals_and_logging(tmp):
    d = os.path.join(tmp, "sig")
    os.makedirs(d)
    assert subprocess.run([SPM, "init"], cwd=d, input=f"{MASTER_PW}\n{MASTER_PW}\n", text=True, capture_output=True).returncode == 0
    assert subprocess.run([SPM, "add", "BANK_SVC"], cwd=d, input=f"{MASTER_PW}\nBANK_USR\nBANK_PASS_99\n", text=True, capture_output=True).returncode == 0

    # Ctrl+Z ignored, Ctrl+C -> n resume mid-Master password, Ctrl+C -> y/2nd/EOF exit 130, Ctrl+D exit 0
    p, m = spawn_pty(d)
    read_until(m, b"spm> ")
    os.write(m, b"\x1a")
    time.sleep(0.1)
    assert os.waitpid(p.pid, os.WNOHANG | os.WUNTRACED) == (0, 0)

    os.write(m, b"list\n")
    read_until(m, b"Master password: ")
    assert not echo_on(m)
    os.write(m, b"\x1a")
    time.sleep(0.1)
    assert os.waitpid(p.pid, os.WNOHANG | os.WUNTRACED) == (0, 0)
    os.write(m, b"half\x03")
    read_until(m, b"Exit cleanly? [y/N]: ")
    assert echo_on(m)
    os.write(m, b"n\n")
    read_until(m, b"Master password: ")
    assert not echo_on(m)
    os.write(m, MASTER_PW.encode() + b"\n")
    assert b"BANK_SVC (user: BANK_USR)" in read_until(m, b"spm> ")
    os.write(m, b"\x04")
    rc, _, echo = wait_tty(p, m)
    assert rc == 0 and echo

    for trig in (b"y\n", b"\x03", b"\x04"):
        p, m = spawn_pty(d)
        read_until(m, b"spm> ")
        os.write(m, b"\x03")
        read_until(m, b"Exit cleanly? [y/N]: ")
        os.write(m, trig)
        rc, _, echo = wait_tty(p, m)
        assert rc == 130 and echo

    for sig, exp in ((signal.SIGTERM, 143), (signal.SIGHUP, 129)):
        p, m = spawn_pty(d)
        read_until(m, b"spm> ")
        os.write(m, b"list\n")
        read_until(m, b"Master password: ")
        assert not echo_on(m)
        os.kill(p.pid, sig)
        rc, _, echo = wait_tty(p, m)
        assert rc == exp and echo

    # Log security checks: mode 0600, strict line schema, zero secrets, 0644 lockdown, symlink & FIFO blocked
    lp = os.path.join(d, "spm.log")
    assert stat.S_IMODE(os.stat(lp).st_mode) == 0o600
    ltxt = open(lp, "r", encoding="utf-8").read()
    for ln in ltxt.splitlines():
        assert LOG_RE.match(ln), f"Bad log line: {ln!r}"
    for secret in (MASTER_PW, "BANK_SVC", "BANK_USR", "BANK_PASS_99"):
        assert secret not in ltxt, f"Secret leaked in spm.log: {secret}"
    for ev_detail in ("clean_exit", "sigint", "sigterm", "sighup"):
        assert f"detail={ev_detail}" in ltxt, f"Missing log detail={ev_detail}"

    os.chmod(lp, 0o644)
    assert subprocess.run([SPM, "list"], cwd=d, input=MASTER_PW + "\n", text=True, capture_output=True).returncode == 0
    assert stat.S_IMODE(os.stat(lp).st_mode) == 0o600

    d_sec = os.path.join(tmp, "logsec")
    os.makedirs(d_sec)
    victim = os.path.join(d_sec, "victim.txt")
    open(victim, "w", encoding="utf-8").write("SAFE\n")
    os.symlink(victim, os.path.join(d_sec, "spm.log"))
    r = subprocess.run([SPM, "init"], cwd=d_sec, input=f"{MASTER_PW}\n{MASTER_PW}\n", text=True, capture_output=True)
    assert r.returncode == 0 and open(victim, encoding="utf-8").read() == "SAFE\n"
    assert "Warning: could not update log file." in r.stderr

    os.unlink(os.path.join(d_sec, "spm.log"))
    os.mkfifo(os.path.join(d_sec, "spm.log"))
    r = subprocess.run([SPM, "list"], cwd=d_sec, input=MASTER_PW + "\n", text=True, capture_output=True, timeout=5)
    assert r.returncode == 0 and "Warning: could not update log file." in r.stderr
    print("[PASS] signal handling, ECHO restoration, and protected spm.log logging")


def test_memory_and_core_dumps(tmp):
    d = os.path.join(tmp, "mem")
    os.makedirs(d)

    def unlim_core():
        resource.setrlimit(resource.RLIMIT_CORE, (1024 * 1024, 1024 * 1024))

    p, m = spawn_pty(d, preexec_extra=unlim_core)
    read_until(m, b"spm> ")
    status_txt = open(f"/proc/{p.pid}/status", encoding="utf-8").read()
    limits_txt = open(f"/proc/{p.pid}/limits", encoding="utf-8").read()
    is_asan = b"__asan_" in open(SPM, "rb").read()
    if os.geteuid() != 0:
        for proc_file in ("maps", "mem"):
            try:
                with open(f"/proc/{p.pid}/{proc_file}", "rb"):
                    raise AssertionError(f"PR_SET_DUMPABLE=0 should block /proc/<pid>/{proc_file}")
            except PermissionError:
                pass
    vmlck = [ln for ln in status_txt.splitlines() if ln.startswith("VmLck:")][0]
    core_line = [ln for ln in limits_txt.splitlines() if ln.startswith("Max core file size")][0]
    assert core_line.split()[4] == "0" and core_line.split()[5] == "0", core_line

    # ASan intercepts mlock() and SIGSEGV for sanitizer runtime safety, so test kernel mlock/core-kill on spm.
    if not is_asan:
        assert int(vmlck.split()[1]) >= 20, vmlck
        os.kill(p.pid, signal.SIGSEGV)
        p.wait(timeout=5)
        os.close(m)
        assert os.listdir(d) == [], f"Unexpected core dump created: {os.listdir(d)}"

        if os.geteuid() != 0:
            def zero_mlock():
                resource.setrlimit(resource.RLIMIT_MEMLOCK, (0, 0))

            r = subprocess.run([SPM, "list"], cwd=d, text=True, capture_output=True, preexec_fn=zero_mlock)
            assert r.returncode == 1 and "Secure memory is unavailable." in r.stderr
    else:
        os.write(m, b"exit\n")
        assert wait_tty(p, m)[0] == 0

    def cap_64k():
        resource.setrlimit(resource.RLIMIT_MEMLOCK, (65536, 65536))

    p, m = spawn_pty(d, preexec_extra=cap_64k)
    read_until(m, b"spm> ")
    os.write(m, b"init\n")
    read_until(m, b"Master password: ")
    os.write(m, MASTER_PW.encode() + b"\n")
    read_until(m, b"Confirm master password: ")
    os.write(m, MASTER_PW.encode() + b"\n")
    assert b"Vault created." in read_until(m, b"spm> ")
    os.write(m, b"add k\n")
    read_until(m, b"Username: ")
    os.write(m, b"u\n")
    read_until(m, b"Password: ")
    os.write(m, b"p\n")
    assert b"Entry saved." in read_until(m, b"spm> ")
    os.write(m, b"exit\n")
    assert wait_tty(p, m)[0] == 0
    print("[PASS] VmLck locking, RLIMIT_MEMLOCK=0 fail-closed, 64KB cap, and core dump prevention")


def main():
    if not os.path.exists(SPM):
        raise FileNotFoundError(f"Binary not found: {SPM}")
    with tempfile.TemporaryDirectory(prefix="spm_suite_") as tmp:
        test_missing_vault_and_help(tmp)
        test_init_and_validation(tmp)
        test_crud_clipboard_and_capacity(tmp)
        test_unlock_retry_and_wipe(tmp)
        test_aad_permissions_and_del_vault(tmp)
        test_signals_and_logging(tmp)
        test_memory_and_core_dumps(tmp)
    print(f"ALL TESTS PASSED ({os.path.basename(SPM)})")


if __name__ == "__main__":
    main()
