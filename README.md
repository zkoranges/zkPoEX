# zkPoEX

![zkPoEX](https://github.com/zkoranges/zkPoEX/blob/main/img.jpg?raw=true)

## Personal Note

After developing the original zkPoEX prototype during ETHDenver, I’ve since had to re-evaluate how best to allocate my time and focus across multiple professional commitments. As a result, the initial working prototype has been archived here: [https://github.com/zkoranges/zkPoEX_archive](https://github.com/zkoranges/zkPoEX_archive). Moving forward, this repository will evolve into a more refined and community-oriented resource based on the lessons and insights gained throughout the project.

**Want to contribute or discuss?** Send me a message on Twitter [@zkoranges](https://twitter.com/zkoranges) if you want to add something to this README.md or if you want to discuss specifics about zkPoEX implementations.

## Overview

zkPoEX (Zero-Knowledge Proof of Exploit) enables security researchers to prove they have discovered vulnerabilities in smart contracts while maintaining complete confidentiality of the exploit details. This revolutionary approach transforms vulnerability disclosure by allowing trustless verification of exploitability without revealing sensitive information that could be misused by malicious actors.

The technology addresses a critical challenge in the DeFi security ecosystem: bug bounty programs are often difficult to maintain, not always honored, and may not provide sufficient compensation for white hat hackers. This lack of incentive leads to unreported vulnerabilities, ultimately resulting in a less secure ecosystem.

## Key Benefits

**Privacy-Preserving Disclosure**: Prove exploit existence without revealing implementation details, protecting both researchers and projects

**Trustless Verification**: Enable automated reward systems and immediate response mechanisms upon proof verification

**Incentive Alignment**: Encourage responsible disclosure through guaranteed, automated compensation mechanisms

**Enhanced Security**: Foster better collaboration between security researchers and project teams by eliminating disclosure risks

## Current Leading Implementations

### SecurFi/zkProver
The SecurFi zkProver represents one of the most comprehensive toolkits currently available, built on RISC Zero with support for multiple platforms including Linux and macOS with Apple Silicon. The system offers hardware acceleration through CUDA and Metal and focuses specifically on Ethereum smart contracts with advanced EVM integration.

**Repository**: [https://github.com/SecurFi/zkProver](https://github.com/SecurFi/zkProver)

**Key Features**:
- Cross-platform support with hardware acceleration
- EVM-focused exploit proving capabilities
- Integration with existing Ethereum development tools
- Command-line interface for streamlined proof generation

### ziemen4/zkpoex
This implementation takes a structured approach, built as a Rust-based toolkit specifically designed for Ethereum smart contracts. The project is organized as a Cargo workspace with four main components: host, methods, evm-runner, and sc-owner.

**Repository**: [https://github.com/ziemen4/zkpoex](https://github.com/ziemen4/zkpoex)

**Technical Architecture**:
- Uses RISC Zero as the underlying zkVM
- Implements comprehensive EVM integration for proving
- Modular design with clear separation of concerns
- Supports trustless bug bounties with automatic reward claiming

## Academic and Research Context

The field benefits from significant academic contributions, particularly from Trail of Bits and Johns Hopkins University through DARPA-funded research. Trail of Bits has developed specialized tools and comprehensive documentation through their ZKDocs project, addressing common implementation issues in cryptographic protocols.

Recent academic work includes the CHEESECLOTH system, which presents a novel proof-statement compiler for proving practical vulnerabilities in zero-knowledge. This system has successfully generated ZK proofs for well-known vulnerabilities including the Heartbleed information leakage in OpenSSL.

## Resources for Further Development

### Technical Documentation
- [RISC Zero Developer Documentation](https://dev.risczero.com/api/)
- [Zero-Knowledge Proofs: An Illustrated Primer](https://blog.cryptographyengineering.com/2014/11/27/zero-knowledge-proofs-illustrated-primer/)
- [zkVM Technical Specification](https://dev.risczero.com/api/zkvm/zkvm-specification)

### Security Analysis
- [Specialized Zero-Knowledge Proof Failures](https://blog.trailofbits.com/2022/11/29/specialized-zero-knowledge-proof-failures/)
- [Zero-Knowledge Proof Vulnerability Analysis](https://eprint.iacr.org/2024/514.pdf)

### Community Resources
- [Awesome Zero-Knowledge Proofs](https://github.com/matter-labs/awesome-zero-knowledge-proofs)
- [ZK Proof Community](https://docs.zkproof.org/)

## Get in Touch

Have ideas, feedback, or want to contribute to this resource? **Send me a message on Twitter [@zkoranges](https://twitter.com/zkoranges)** – I'd love to hear from you and discuss how we can make this resource even better for the zkPoEX community.

---

**Original Prototype**: The working prototype that won at ETHDenver has been preserved at [https://github.com/zkoranges/zkPoEX_archive](https://github.com/zkoranges/zkPoEX_archive) for reference and historical context.

**License**: MIT License - See individual project repositories for specific licensing terms.

**Disclaimer**: zkPoEX implementations are experimental and provided for educational and research purposes only. They are not intended for production use without comprehensive security audits. Users are solely responsible for ensuring their use of this code complies with all applicable laws and regulations in their jurisdiction. Always act responsibly and respect the law.
