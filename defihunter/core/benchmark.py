"""Historical-exploit benchmark: does the analyzer catch the bug classes
that actually stole money?

Each case is a small, self-contained Solidity contract encoding a REAL
historical vulnerability class (The DAO 2016, Parity 2017, OZ initializer
2021, …). ``run_benchmark()`` analyzes every fixture with the same
``analyze_repo_dir`` used in production and scores detection. A clean
control contract must produce NO HIGH/CRITICAL findings — a guarded vault
must not raise alarms.

This is the credibility artifact behind the "fork-proves every HIGH
finding" claim: we can point at a score like "detected 10/10 historical
exploit classes, 0 false positives on the clean vault".
"""

from pathlib import Path
from tempfile import TemporaryDirectory

from defihunter.core.analyzer import analyze_repo_dir

# Each fixture: id + reference to the real-world incident, the analyzer
# signals it MUST emit, and a minimal contract encoding the bug class.
# expect entries are (severity, attack) pairs matching analyzer findings.
HISTORICAL_CASES = [
    {
        "id": "dao-reentrancy-2016",
        "ref": "The DAO, Jun 2016 — ~$60M drained by reentrant withdraw",
        "expect": [("MEDIUM", "reentrancy")],
        "source": """
pragma solidity ^0.8.0;
contract DaoVault {
    mapping(address => uint256) public balances;
    function deposit() public payable { balances[msg.sender] += msg.value; }
    function withdraw(uint256 _amount) public {
        require(balances[msg.sender] >= _amount);
        (bool ok, ) = msg.sender.call{value: _amount}("");
        require(ok, "send failed");
        balances[msg.sender] -= _amount;   // state updated AFTER the call
    }
}
""",
    },
    {
        "id": "parity-delegatecall-2017",
        "ref": "Parity multi-sig, Jul 2017 — ~$30M frozen via delegatecall",
        "expect": [("HIGH", "delegatecall")],
        "source": """
pragma solidity ^0.8.0;
contract Wallet {
    address public owner;
    function execute(address _target, bytes calldata _data) public returns (bool) {
        (bool ok, ) = _target.delegatecall(_data);  // runs _target code in OUR storage
        return ok;
    }
}
""",
    },
    {
        "id": "oz-initializer-2021",
        "ref": "Proxy clobbering class — unguarded initialize() lets first caller own the proxy",
        "expect": [("HIGH", "initialize")],
        "source": """
pragma solidity ^0.8.0;
contract ProxyVault {
    address public owner;
    bool private initialized;
    function initialize(address _owner) public {
        // no initializer modifier / no require guard — first caller wins
        owner = _owner;
    }
}
""",
    },
    {
        "id": "txorigin-phishing-2018",
        "ref": "tx.origin auth — malicious contract calls in the victim's name",
        "expect": [("HIGH", "admin")],
        "source": """
pragma solidity ^0.8.0;
contract Bank {
    address public owner;
    function transferAll() public {
        require(tx.origin == owner, "owner only");  // bypassable via phishing
        payable(owner).transfer(address(this).balance);
    }
}
""",
    },
    {
        "id": "flashloan-oracle-2021",
        "ref": "Spot-price oracle (PancakeBunny 2021 class) — flash-loan manipulable",
        "expect": [("MEDIUM", "oracle")],
        "source": """
pragma solidity ^0.8.0;
contract SwapVault {
    function getPrice(address pool) public view returns (uint256) {
        (uint112 r0, uint112 r1, ) = IPair(pool).getReserves();  // one-block manipulable
        return r1 * 1e18 / r0;
    }
}
""",
    },
    {
        "id": "hardcoded-private-key",
        "ref": "Private key committed to source — instantly spendable funds",
        "expect": [("HIGH", None)],
        "source": """
pragma solidity ^0.8.0;
contract Signer {
    bytes32 private constant PRIVATE_KEY =
        0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d;
    function sign(bytes32 hash) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(hash, PRIVATE_KEY));
    }
}
""",
    },
    {
        "id": "selfdestruct-kill-2017",
        "ref": "Permissionless kill switch — balance force-sent, code destroyed",
        "expect": [("CRITICAL", "admin")],
        "source": """
pragma solidity ^0.8.0;
contract Killable {
    address public owner;
    function kill() public { selfdestruct(payable(owner)); }
}
""",
    },
    {
        "id": "unguarded-mint",
        "ref": "mint() with no access control — unlimited supply by anyone",
        "expect": [("HIGH", "mint")],
        "source": """
pragma solidity ^0.8.0;
contract Token {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    function mint(address to, uint256 amount) public {   // no onlyOwner
        balanceOf[to] += amount;
        totalSupply += amount;
    }
}
""",
    },
    {
        "id": "timestamp-gate",
        "ref": "block.timestamp gates state changes — miner/validator skew",
        "expect": [("LOW", None)],
        "source": """
pragma solidity ^0.8.0;
contract Lottery {
    uint256 public deadline;
    function claim() public {
        require(block.timestamp < deadline, "too late");  // timestamp-dependent
    }
}
""",
    },
    {
        "id": "hardcoded-64hex-secret",
        "ref": "64-hex literal in source — private key or secret hash",
        "expect": [("HIGH", None)],
        "source": """
pragma solidity ^0.8.0;
contract OracleSigner {
    bytes32 internal constant SECRET =
        0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;
    function reveal() public pure returns (bytes32) { return SECRET; }
}
""",
    },
    {
        "id": "control-clean-vault",
        "ref": "Clean control — guarded vault must NOT raise HIGH/CRITICAL",
        "control": True,
        "expect": [],
        "source": """
pragma solidity ^0.8.0;
contract GuardedVault {
    address public owner;
    bool private initialized;
    mapping(address => uint256) public balances;
    modifier onlyOwner() { require(msg.sender == owner, "!owner"); _; }
    constructor() { owner = msg.sender; }
    function initialize(address _owner) public {
        require(!initialized, "already");
        initialized = true;
        owner = _owner;
    }
    function mint(address to, uint256 amount) external onlyOwner {
        balances[to] += amount;
    }
}
""",
    },
]


def _case_detected(findings: list, case: dict) -> tuple:
    """(detected, hits, missed) for one case against its expected signals."""
    expected = set(tuple(e) for e in case.get("expect", []))
    hits = set()
    for sev, attack in expected:
        if any(f.get("severity") == sev and f.get("attack") == attack
               for f in findings):
            hits.add((sev, attack))
    if case.get("control"):
        # a clean contract must produce no HIGH/CRITICAL findings at all
        bad = [f for f in findings
               if f.get("severity") in ("CRITICAL", "HIGH")]
        if bad:
            return (False, hits, [("CRITICAL/HIGH", "unexpected")])
        return (True, hits, [])
    missed = set(expected) - hits
    return (len(missed) == 0, hits, missed)


def run_benchmark() -> list:
    """Analyze every historical fixture and return per-case verdicts."""
    results = []
    for case in HISTORICAL_CASES:
        with TemporaryDirectory(prefix="defihunter-bench-") as td:
            Path(td, "Case.sol").write_text(case["source"].lstrip("\n"))
            findings = analyze_repo_dir(td, repo_label=case["id"])
        detected, hits, missed = _case_detected(findings, case)
        results.append({
            "id": case["id"],
            "ref": case["ref"],
            "control": bool(case.get("control")),
            "detected": detected,
            "hits": sorted(hits),
            "missed": sorted(missed),
            "findings": findings,
        })
    return results


def summarize(results: list) -> dict:
    """Detection score + false-positive count on the clean control."""
    total = len(results)
    detected = sum(1 for r in results if r["detected"])
    controls = [r for r in results if r["control"]]
    fp = [r for r in controls if not r["detected"]]
    return {
        "total": total,
        "detected": detected,
        "pct": int(100 * detected / max(total, 1)),
        "control_count": len(controls),
        "false_positives": len(fp),
    }
