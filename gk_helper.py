"""Entry point of the Game Kernel helper process (``gk-helper.exe`` when frozen).

Started only by the Game Kernel application (or by tests) with stdin/stdout pipes speaking
gk-ipc v1 — see docs/INTEGRATION.md. It is not meant to be run by hand.
"""

import os
import sys

if not getattr(sys, "frozen", False):
    # Development: started as ``python -I gk_helper.py``; -I does not add the script folder to
    # sys.path, so add this file's own (absolute) directory — never the current directory.
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gamekernel import netguard  # noqa: E402  (must run before any other import)

netguard.install()

import multiprocessing  # noqa: E402

if __name__ == "__main__":
    multiprocessing.freeze_support()
    from gamekernel.ipc.helper import main

    sys.exit(main())
