"""Checks smtp-net's DKIM signatures with dkimpy, an independent verifier.

Usage: dkim_verify.py <corpus dir>, written by `tests/dkim.rs` with
SMTP_NET_DKIM_CORPUS set. `pass-*.eml` must verify (every signature);
`fail-*.eml` were changed after signing and must not.
"""

import pathlib
import sys

import dkim


def main(corpus: str) -> int:
    root = pathlib.Path(corpus)
    records = {}
    for line in (root / "records.txt").read_text().splitlines():
        name, value = line.split("\t", 1)
        records[name.lower().rstrip(".")] = value.encode()

    def check(verifier, i):
        try:
            return verifier.verify(idx=i, dnsfunc=dnsfunc)
        except dkim.DKIMException as e:
            return f"refused: {e}"

    def dnsfunc(name, timeout=5):
        if isinstance(name, bytes):
            name = name.decode()
        return records.get(name.lower().rstrip("."), b"")

    checked = wrong = 0
    for path in sorted(root.glob("*.eml")):
        message = path.read_bytes()
        head = message.split(b"\r\n\r\n", 1)[0]
        count = sum(1 for line in head.split(b"\r\n") if line.lower().startswith(b"dkim-signature:"))
        verifier = dkim.DKIM(message)
        results = [check(verifier, i) for i in range(count)]
        verified = count > 0 and all(r is True for r in results)
        expected = path.name.startswith("pass-")
        if verified != expected:
            wrong += 1
            print(f"WRONG {path.name}: signatures {results}")
        checked += 1
    print(f"{checked} messages checked by dkimpy {getattr(dkim, '__version__', '')}, {wrong} wrong")
    return 1 if wrong or checked == 0 else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
