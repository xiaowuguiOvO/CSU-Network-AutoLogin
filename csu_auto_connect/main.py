from __future__ import annotations

import sys

from csu_auto_connect.ui import run


def main() -> None:
    raise SystemExit(run(sys.argv[1:]))


if __name__ == "__main__":
    main()
