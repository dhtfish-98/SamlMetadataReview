from .common import main
from .audit import audit
def entry():
    raise SystemExit(main(audit))
