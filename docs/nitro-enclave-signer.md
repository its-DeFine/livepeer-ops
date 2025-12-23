# Nitro Enclaves signer (KMS-unseal)

This document describes how to run the **Payments remote signer** inside an **AWS Nitro Enclave**, with the Ethereum key **unsealed from AWS KMS** (so the parent instance IAM role cannot decrypt it in plaintext).

## What runs where

- **Parent instance (untrusted)**: Payments backend (FastAPI, Docker) + `vsock-proxy` to AWS KMS.
- **Enclave (trusted)**: `enclave/signer_server.py` (holds the ETH key in enclave memory, serves signing RPC over vsock).

## Prereqs

- An **enclave-capable EC2 instance type** (Nitro Enclaves support must be `supported`).
- Installed on the parent:
  - `docker`
  - `nitro-cli` + `nitro-enclaves-allocator`
  - `vsock-proxy` (ships with Nitro Enclaves CLI packages)
- A KMS key policy that allows **Decrypt only with Recipient attestation** (PCR0/ImageSha384 locked).

## 1) Build kmstool artifacts (parent)

On the parent instance, from the Payments repo:

```bash
cd /home/ubuntu/payments/backend
./scripts/fetch_kmstool_enclave_cli.sh
```

This writes:
- `enclave/kmstool_enclave_cli`
- `enclave/libnsm.so`

These files are ignored by git.

## 2) Build the EIF (parent)

```bash
nitro-cli build-enclave --docker-dir enclave --output-file enclave-signer.eif
```

Save the printed **PCR0** (or `ImageSha384`) for the KMS key policy.

## 3) Run a KMS vsock proxy (parent)

Run in `tmux`:

```bash
sudo vsock-proxy 8000 kms.us-east-2.amazonaws.com 443
```

Use the same port you pass as `proxy_port` when provisioning (default `8000`).

## 4) Run the enclave (parent)

```bash
nitro-cli run-enclave --cpu-count 2 --memory 512 --eif-path enclave-signer.eif
nitro-cli describe-enclaves
```

Grab the `EnclaveCID` (often `16`).

## 5) Encrypt the ETH key (outside enclave)

Encrypt a 0x-prefixed 32-byte private key string with KMS:

```bash
PLAINTEXT="0x0123...<64 hex>..."
aws kms encrypt --key-id "$KMS_KEY_ARN" --plaintext "$PLAINTEXT" --query CiphertextBlob --output text
```

The output is a base64 `CiphertextBlob` (safe to store on the parent).

## 6) Provision the enclave signer (parent)

This sends:
- the ciphertext blob
- temporary AWS credentials (from IMDSv2)

to the enclave, which then calls KMS (via `vsock-proxy`) and keeps the plaintext key inside enclave memory.

```bash
python3 ./scripts/provision_enclave_signer.py \
  --endpoint vsock://<ENCLAVE_CID>:5000 \
  --region us-east-2 \
  --ciphertext-b64 '<CiphertextBlob base64>'
```

It returns the signer `address`.

### Optional: signer policy (recommended)

To reduce blast radius if the HTTP backend is compromised, you can provision a policy so the enclave will **only sign**:
- `TicketBroker.fundDeposit()` (optional)
- `TicketBroker.redeemWinningTicket(...)`
- `TicketBroker.batchRedeemWinningTickets(...)`

Example (Arbitrum mainnet):

```bash
python3 ./scripts/provision_enclave_signer.py \
  --endpoint vsock://<ENCLAVE_CID>:5000 \
  --region us-east-2 \
  --ciphertext-b64 '<CiphertextBlob base64>' \
  --chain-id 42161 \
  --ticket-broker 0xa8bb618b1520e284046f3dfc448851a1ff26e41b \
  --allowed-recipient 0x... \
  --require-allowlist \
  --max-face-value-eth 0.05
```

## 7) Point Payments backend at the signer

Set in Payments `.env`:

```bash
PAYMENTS_SIGNER_ENDPOINT=vsock://<ENCLAVE_CID>:5000
PAYMENTS_SIGNER_EXPECTED_ADDRESS=0x...
```

Then restart Payments.

Note: Docker containers often can open `AF_VSOCK` sockets, but if this fails you may need to run Payments with host networking or add a small host-side tcp↔vsock bridge.

## KMS key policy sketch (least privilege)

You want the instance role to be able to call `kms:Decrypt` **only when** the request includes a Recipient attestation document matching your enclave measurement.

Minimal shape:

- allow `kms:Decrypt` to the **instance role**
- require `kms:RecipientAttestation:PCR0` (or `kms:RecipientAttestation:ImageSha384`) equals your EIF measurement
- optionally require an `kms:EncryptionContext:*` pair (ex: `service=payments-signer`)

Do not grant plaintext decrypt to other principals.

### Concrete KMS policy template

Save the PCR0 from `nitro-cli build-enclave ...` and create a CMK with a key policy like:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowKmsAdmin",
      "Effect": "Allow",
      "Principal": { "AWS": "KMS_ADMIN_ROLE_ARN" },
      "Action": [
        "kms:Create*",
        "kms:Describe*",
        "kms:Enable*",
        "kms:List*",
        "kms:Put*",
        "kms:Update*",
        "kms:Revoke*",
        "kms:Disable*",
        "kms:Get*",
        "kms:Delete*",
        "kms:TagResource",
        "kms:UntagResource",
        "kms:ScheduleKeyDeletion",
        "kms:CancelKeyDeletion"
      ],
      "Resource": "*"
    },
    {
      "Sid": "AllowEncryptFromInstanceRole",
      "Effect": "Allow",
      "Principal": { "AWS": "INSTANCE_ROLE_ARN" },
      "Action": ["kms:Encrypt"],
      "Resource": "*"
    },
    {
      "Sid": "AllowDecryptOnlyFromEnclaveMeasurement",
      "Effect": "Allow",
      "Principal": { "AWS": "INSTANCE_ROLE_ARN" },
      "Action": ["kms:Decrypt"],
      "Resource": "*",
      "Condition": {
        "StringEqualsIgnoreCase": {
          "kms:RecipientAttestation:PCR0": "PCR0_HEX_FROM_EIF_BUILD"
        }
      }
    }
  ]
}
```

Notes:
- In production, prefer `kms:RecipientAttestation:ImageSha384` if you’re pinning on that value instead of PCR0.
- For production, you typically **don’t** grant `kms:Encrypt` to the instance role; you encrypt the secret out-of-band.

### Instance role IAM permissions

The instance role still needs IAM permissions to call KMS APIs. Keep this tight to the key ARN:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["kms:Decrypt", "kms:Encrypt"],
      "Resource": "KMS_KEY_ARN"
    }
  ]
}
```
