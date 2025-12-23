# Nitro Enclaves signer (WIP)

This folder contains the **signer side** of the Payments TEE design:

- Runs inside an AWS Nitro Enclave and holds the Ethereum private key in enclave memory.
- Exposes the same length-prefixed JSON RPC used by `payments/signer.py` (`tcp://` or `vsock://`).

Status: this repo currently ships **backend-side plumbing** (remote signer client + `/api/tee/*` endpoints).
The enclave signer build/run steps live in `docs/nitro-enclave-signer.md`.

