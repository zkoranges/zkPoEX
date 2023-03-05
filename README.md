
# zkPoEX

![zkPoEX](https://github.com/zkoranges/zkPoEX/blob/main/img.jpg?raw=true)

zkPoEX (zk proof of exploit) aims to facilitate communication and collaboration between security experts and project owners in the decentralized finance (DeFi) space by enabling white hat hackers to report live vulnerabilities in smart contracts while maintaining the confidentiality of the exploit.

## Problem

Bug bounty programs in the DeFi space can be hard to run and maintain, not always honored, and may not always offer sufficient compensation for white hats. This can lead to a lack of incentive for hackers to report vulnerabilities, which can ultimately result in a less secure DeFi ecosystem.

## Solution

Our tooling allows auditors to safely generate a zero-knowledge proof of exploit without revealing the actual exploit. With zero-knowledge proofs, the auditor can prove that they know of a transaction that can produce an undesirable change of state in certain contracts, without revealing the specifics of the exploit.

Since the auditor is not giving away the exploit, the project is incentivized to work with the auditor to fix the vulnerability. This facilitates communication and collaboration between hackers and project owners for a more secure DeFi ecosystem.

![zkPoEX](https://github.com/zkoranges/zkPoEX/blob/main/diagram.jpg?raw=true)


## Technologies Used

The project utilizes the following technologies:

-   [SputnikVM](https://sputnikvm.com/): A high-performance, modular virtual machine for executing Ethereum smart contracts.
-   [Risc0](https://risc-0.com/): A General Purpose Zero-Knowledge VM that allows to prove and verify any computation. The RISC Zero ZKVM is a verifiable computer that works like a real embedded RISC-V microprocessor, enabling programmers to write ZK proofs like they write any other code.
-   [Zero-Knowledge Proofs](https://en.wikipedia.org/wiki/Zero-knowledge_proof): A cryptographic technique that allows one party to prove to another party that a statement is true, without revealing any additional information beyond the fact that the statement is true.

## Installation and Setup

To use the project, you will need to have the following installed on your system:

- [Rust](https://www.rust-lang.org/tools/install)
- [Solc](https://docs.soliditylang.org/en/v0.8.17/installing-solidity.html)
- [Just](https://github.com/casey/just)

To test the evm :
```bash
$ test-evm
```
To generate proof (and verify) :
```bash
$ just prove
```

## Acknowledgements:

We would like to thank Maciej Zieliński for providing an example in his [blog post](https://odra.dev/blog/evm-at-risc0/) of how to run Solidity code inside SputnikVM inside Risc0. 


## Contributing

Contributions to the project are welcome and encouraged. To contribute, fork the project on GitHub, make your changes, and submit a pull request.
