from pathlib import Path
from dotenv import load_dotenv
import os, sys

here = Path(__file__).resolve().parent / "sentinel" / "cli.py"
here = here.parent
for directory in [here, here.parent, here.parent.parent]:
    for name in [".env.local", ".env"]:
        c = directory / name
        if c.exists():
            load_dotenv(c)
            print(f"Loaded env from: {c}", flush=True)
            break
    else:
        continue
    break

uri = os.environ.get("MONGODB_URI", "")
print(f"URI present: {bool(uri)}", flush=True)
if not uri:
    print("ERROR: MONGODB_URI not found", flush=True)
    sys.exit(1)

from sentinel.memory_store import MemoryStore
store = MemoryStore()
try:
    store.ping()
    print("Atlas ping: OK", flush=True)
except Exception as e:
    print(f"Atlas ping FAILED: {type(e).__name__}: {e}", flush=True)
finally:
    store.close()
