
`Static Analysis Tools` for Smart Contracts (Solidity, Vyper, etc.)

These tools analyze code without executing it.
```
Open Source
- Slither       Static analysis
- Mythril       Symbolic Executor
- Securify      Theoritical Formal Verification
- Mantocore     Symbolic Executor
- Echidna       Property-based fuzzing
```
| **Criteria**            | **Slither**                 | **Mythril**                             | **Manticore**                               | **Echidna**                                  |
| ----------------------- | --------------------------- | --------------------------------------- | ------------------------------------------- | -------------------------------------------- |
| **Type**                | Static Analyzer             | Symbolic Execution + Static Analysis    | Symbolic Execution Engine                   | Property-Based Fuzzer                        |
| **Speed**               | ⚡ Very Fast                 | 🐢 Medium                               | 🐌 Slow                                     | 🐢 Medium to Slow                            |
| **Depth**               | ⚠️ Medium                   | ✅ High                                  | ✅ Very High                                 | ✅ High                                       |
| **Detect Runtime Bugs** | ❌ No                        | ✅ Yes                                   | ✅ Yes                                       | ✅ Yes                                        |
| **Language**            | Python                      | Python                                  | Python                                      | Haskell (test contracts written in Solidity) |
| **Fuzzing**             | ❌ No                        | ⚠️ Limited (concolic inputs)            | ⚠️ Limited (custom, script-driven)          | ✅ Yes (native fuzzing with properties)       |
| **Symbolic Execution**  | ❌ No                        | ✅ Yes                                   | ✅ Yes                                       | ❌ No                                         |
| **Static Analysis**     | ✅ Yes                       | ✅ Partial                               | ⚠️ Minimal                                  | ❌ No                                         |
| **Setup**               | ✅ Easy (pip or Docker)      | ⚠️ Moderate (Python + solc setup)       | ❌ Complex (manual EVM setup, scripting)     | ⚠️ Moderate (Haskell tools or Docker)        |
| **Reporting**           | ✅ Clean CLI + JSON          | ⚠️ CLI-based logs, JSON possible        | ❌ Raw output (scripting needed for reports) | ⚠️ CLI logs; no built-in structured reports  |
| **Manual Intervention** | ❌ Minimal (fully automatic) | ⚠️ Medium (tuning symbolic depth, etc.) | ✅ High (write scripts for deep analysis)    | ✅ High (you must define good properties)     |
| **CLI / GUI**           | ✅ CLI only                  | ✅ CLI only                              | ✅ CLI only                                  | ✅ CLI only                                   |


-  Slither - Slither is a Solidity & Vyper static analysis framework written in Python3. It runs a suite of vulnerability detectors, prints visual information about contract details, and provides an API to easily write custom analyses. Slither enables developers to find vulnerabilities, enhance their code comprehension, and quickly prototype custom analyses. 

```
Type	            Static Analysis Tool for Solidity
Strengths	        Fast, reliable, extendable, clear reporting
Weaknesses	        No runtime analysis, false positives, Command-line only;
Ideal Use Case	    Pre-deployment auditing and CI integration
OS	                Windows, macOS, Linux
Languages	        Python 3.8+

- Writing custom detectors requires Python and Slither IR knowledge.
```

https://github.com/crytic/slither


-  Mythril: Mythril is a `symbolic-execution-based` security analysis tool for EVM bytecode. It performs symbolic execution, taint analysis, and control flow checking to detect vulnerabilities in smart contracts written in Solidity, Vyper, and EVM bytecode. Developed and maintained by ConsenSys Diligence, Mythril is widely used in security audits of Ethereum DApps.
```
Operating Systems	        Windows, macOS, Linux
Languages	                Python 3.8+
Smart Contract Languages	Solidity, Vyper, EVM bytecode
Slow Analysis	            Symbolic execution is resource-intensive and slower than static tools like Slither.
No Full CI/CD Integration	Not as seamless to integrate in pipelines as Slither (though possible).
No GUI	                    Only CLI-based unless paired with other tools like MythX (SaaS).
```

https://github.com/ConsenSysDiligence/mythril

-  Securify v2.0: Securify 2.0 is a security scanner for Ethereum smart contracts supported by the Ethereum Foundation and ChainSecurity. The core research behind Securify was conducted at the Secure, Reliable, and Intelligent Systems Lab at ETH Zurich.

```
Operating Systems	    Linux, macOS, Windows (via Docker)
Languages	            Solidity
Interface	            Web-based interface (via local Docker) or CLI
Bytecode Support	    Can work with contracts even if only the bytecode is available.
Slow Analysis	        Slower than symbolic analyzers like Mythril or static tools like Slither..
Outdated	            Project updates are less frequent; may not support latest Solidity features.
Dependency Handling	    Struggles with large projects with multiple imports unless manually configured.
Environment Conflicts	Needs Docker; can be incompatible with some dev environments without container support.
```



- Solhint

Solhint is a static analysis tool specifically designed for Solidity, the programming language used for Ethereum smart contracts

https://github.com/protofire/solhint

```
Operating Systems	        Windows, macOS, Linux
Languages	                Solidity (for contracts), JavaScript (runtime)
Installation	            Node.js environment (installed via npm)
Interface	                Command Line Interface (CLI)
Not a Security Analyzer	    It checks for best practices but doesn’t simulate or deeply analyze contracts like Mythril or Slither.
Rule Overhead	            Too many rules may cause "lint fatigue" with excessive warnings.
```


`Dynamic Analysis Tools` / `Fuzz testing`

These tools test code during execution to identify runtime issues.

- Echidna

Echidna is a property-based fuzzing tool for Ethereum smart contracts. It is used to automatically test smart contracts written in Solidity by generating random and semi-random inputs to find violations of user-defined security properties. and is used in advanced security testing of decentralized applications (DApps).

```
Operating Systems	            Linux (native), macOS (via Docker), Windows (via WSL or Docker)
Languages	                    Solidity (contract), Haskell (internally), CLI for interaction
Installation	                Via Docker (recommended), or compiled from source
Frameworks Supported	        Compatible with Hardhat, Foundry, Truffle (with configuration)
Property-based Testing	        Developers define security invariants and Echidna tries to break them.
Detects Subtle Bugs	            Useful for finding issues missed by static or symbolic tools (e.g., assertion failures, gas griefing).
Requires Custom Instrumentation	You must write specific echidna_* property functions. Effectiveness depends on defining strong echidna_* checks.
May Miss Logic Bugs	            Will only test the properties you define — not a complete audit on its own.
```

- Manticore

Manticore is an open-source `symbolic execution tool` developed by Trail of Bits. It analyzes Ethereum smart contracts and binaries to discover security vulnerabilities by exploring all possible execution paths. 	Community supported and maintained by Trail of Bits.

```
Operating Systems	    Linux, macOS, Windows (via WSL or Docker)
Languages	            Supports EVM bytecode (Solidity, Vyper), x86, ARM binaries
Interface	            Command-line and Python scripting
Symbolic Execution	    Explores many execution paths automatically by solving constraints.
Python API	            Allows highly customizable analysis via scripting.
Binary + EVM Support	Works on both Ethereum contracts and native binaries (x86/ARM).
Requires Compilation	Only analyzes EVM bytecode — needs correct Solidity compilation.
Limited CI Use	        Not ideal for fast feedback in CI/CD due to slow runtime.
```

- Foundry

Foundry is a fast, portable, and modular toolkit for Ethereum smart contract development, testing, and auditing.
It’s written in Rust, and includes tools for compiling, testing, deploying, fuzzing, and debugging Solidity smart contracts. Foundry is popular among security researchers, auditors, and Solidity developers because it’s fast, scriptable, and fully on-chain-compatible.