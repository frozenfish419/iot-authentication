ProVerif Model for IoT Ownership Transfer Protocol

This repository contains a formal verification model for the proposed IoT ownership transfer and authentication protocol.

Files

- iot_auth.pv
  A ProVerif specification modeling the registration and ownership transfer phases of the protocol. The model captures Diffie–Hellman–based session key establishment, authenticated message exchange, and the use of a device-bound signing key during ownership transfer.

- result.png
  A screenshot of the ProVerif execution results, showing that the specified security queries are successfully verified.

Verification Goals

The ProVerif model is used to validate the following security properties under the Dolev–Yao adversary model:

- Secrecy of session-protected data

- Resistance to message forgery without valid cryptographic credentials

- Correct binding between session establishment and ownership transfer messages

Usage

The model can be verified using ProVerif by executing the specification file. The expected result indicates that all declared secrecy queries hold.
