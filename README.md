# IoT Ownership Binding Protocol: Prototype and ProVerif Models

This repository provides the prototype implementation and formal verification scripts for the IoT device onboarding and ownership binding protocol proposed in our manuscript.

The repository is organized into two main parts:

* `iot\_demo/`: prototype implementation and experimental evaluation code.
* `proverif/`: ProVerif scripts for symbolic security verification.

## Repository Structure

```text
.
├── iot\_demo/
│   ├── README.md
│   └── ...
├── proverif/
│   ├── README.md
│   └── ...
└── README.md
```

## Contents

### 1\. Prototype Implementation

The `iot\_demo/` directory contains the prototype implementation of the proposed protocol.

It includes the main protocol procedures for IoT device onboarding, mutual authentication, session key establishment, and ownership binding. The implementation is used to evaluate the practical performance of the proposed scheme on the experimental platform described in the manuscript.

For build instructions, dependencies, running examples, and experimental details, please refer to:

```text
iot\_demo/README.md
```

### 2\. Formal Verification

The `proverif/` directory contains the ProVerif scripts used to symbolically verify the security properties of the proposed protocol under the Dolev--Yao adversary model.

The verified properties include:

* session key secrecy;
* authentication between the IoT device and the management center;
* resistance to replay attacks;
* resistance to message manipulation attacks within the symbolic model.

For details about the ProVerif model, queries, and verification commands, please refer to:

```text
proverif/README.md
```

## Experimental Environment

The prototype implementation was evaluated in an IoT-oriented experimental environment.

The device-side implementation was tested on an RK3566 development board running Ubuntu 20.04. The management-center side was simulated on a PC platform. Detailed configuration, compilation, and execution instructions are provided in the `iot\_demo/` directory.

## How to Use This Repository

Clone the repository:

```bash
git clone https://github.com/frozenfish419/iot-authentication.git
cd iot-authentication
```

To run the prototype implementation:

```bash
cd iot\_demo
```

Then follow the instructions in `iot\_demo/README.md`.

To run the ProVerif verification scripts:

```bash
cd proverif
```

Then follow the instructions in `proverif/README.md`.

## Reproducibility

This repository is intended to support the reproducibility of the experimental and formal verification results reported in the manuscript.

The prototype implementation can be used to reproduce the protocol execution and timing measurements. The ProVerif scripts can be used to reproduce the symbolic verification results.

When reporting or comparing results, please use the same experimental environment and parameter settings described in the manuscript and in the corresponding directory-level README files.

## License

This repository is provided for academic review and reproducibility purposes.

A formal open-source license may be added in a later version. If a license file is added, the terms in the `LICENSE` file shall apply.

## Contact

For questions about this repository, please contact the corresponding author of the manuscript.

