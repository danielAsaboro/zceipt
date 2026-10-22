"""python3 -m specverify RECEIPT_FILE RAW_TX_HEX_FILE [--testnet|--mainnet]"""

import json
import sys

from . import receipt as rc
from .verify import Invalid, verify


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    coin = 133 if "--mainnet" in argv else 1
    text = open(argv[0]).read().strip()
    raw = bytes.fromhex(open(argv[1]).read().strip())
    try:
        report = verify(rc.b64decode(text[len("zip311r1"):]) if text.startswith("zip311r1") else bytes.fromhex(text), raw, coin)
    except (Invalid, rc.DecodeError, ValueError) as e:
        print(json.dumps({"valid": False, "error": str(e)}))
        return 1
    print(json.dumps({"valid": "if the proofs verify", **report}, indent=2))
    return 0


sys.exit(main(sys.argv[1:]))
