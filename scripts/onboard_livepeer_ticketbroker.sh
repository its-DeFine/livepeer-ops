#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  ./scripts/onboard_livepeer_ticketbroker.sh [--env-file PATH] [--skip-compose] [--run-demo ...]

Starts the payments backend with Livepeer TicketBroker payout mode enabled, and optionally runs a demo payout.

Options:
  --env-file PATH          Path to .env file (default: ./\.env)
  --skip-compose           Do not run docker compose (only edits/creates .env and prints next steps)
  --no-wait                Do not wait for /docs to respond after compose up

Demo options (requires a funded sender key + TicketBroker deposit):
  --run-demo
  --recipient 0x...        Recipient address (required with --run-demo)
  --amount-eth N.N         Amount in ETH (required with --run-demo)
  --private-key-file PATH  File containing the hex private key OR JSON {"private_key": "..."} (required with --run-demo)
  --rpc-url URL            Override ETH RPC URL (passed to demo script)
  --chain-id ID            Override chain id (passed to demo script)
  --ticket-broker 0x...    Override TicketBroker address (passed to demo script)
  --fund-deposit-eth N.N   Optional: fund TicketBroker deposit before payout (passed to demo script)
  --wait                   Wait for onchain receipts (passed to demo script)

Examples:
  ./scripts/onboard_livepeer_ticketbroker.sh

  ./scripts/onboard_livepeer_ticketbroker.sh --run-demo \
    --recipient 0x1111111111111111111111111111111111111111 \
    --amount-eth 0.001 \
    --private-key-file ~/secrets/livepeer_sender_key.txt \
    --wait
EOF
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

ENV_FILE="${ROOT_DIR}/.env"
SKIP_COMPOSE=0
WAIT_FOR_DOCS=1
RUN_DEMO=0

RECIPIENT=""
AMOUNT_ETH=""
PRIVATE_KEY_FILE=""
RPC_URL=""
CHAIN_ID=""
TICKET_BROKER=""
FUND_DEPOSIT_ETH=""
DEMO_WAIT=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --env-file) ENV_FILE="$2"; shift 2 ;;
    --skip-compose) SKIP_COMPOSE=1; shift ;;
    --no-wait) WAIT_FOR_DOCS=0; shift ;;
    --run-demo) RUN_DEMO=1; shift ;;
    --recipient) RECIPIENT="$2"; shift 2 ;;
    --amount-eth) AMOUNT_ETH="$2"; shift 2 ;;
    --private-key-file) PRIVATE_KEY_FILE="$2"; shift 2 ;;
    --rpc-url) RPC_URL="$2"; shift 2 ;;
    --chain-id) CHAIN_ID="$2"; shift 2 ;;
    --ticket-broker) TICKET_BROKER="$2"; shift 2 ;;
    --fund-deposit-eth) FUND_DEPOSIT_ETH="$2"; shift 2 ;;
    --wait) DEMO_WAIT=1; shift ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

EXAMPLE_FILE="${ROOT_DIR}/.env.example"
if [[ ! -f "${ENV_FILE}" ]]; then
  cp "${EXAMPLE_FILE}" "${ENV_FILE}"
  echo "Created ${ENV_FILE} from ${EXAMPLE_FILE}"
fi

ensure_kv() {
  local key="$1"
  local value="$2"
  if grep -qE "^${key}=" "${ENV_FILE}"; then
    return 0
  fi
  printf "\n%s=%s\n" "${key}" "${value}" >>"${ENV_FILE}"
}

# Defaults: enable Livepeer TicketBroker payout strategy (safe to override by editing .env).
ensure_kv "PAYMENTS_PAYOUT_STRATEGY" "livepeer_ticket"
ensure_kv "PAYMENTS_LIVEPEER_TICKET_BROKER_ADDRESS" "0xa8bb618b1520e284046f3dfc448851a1ff26e41b"
ensure_kv "ETH_CHAIN_ID" "42161"
ensure_kv "ETH_RPC_URL" "https://arb1.arbitrum.io/rpc"

COMPOSE_CMD=()
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  COMPOSE_CMD=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE_CMD=(docker-compose)
fi

if [[ "${SKIP_COMPOSE}" -eq 0 ]]; then
  if [[ ${#COMPOSE_CMD[@]} -eq 0 ]]; then
    echo "docker compose not found (install Docker Desktop / docker-compose)." >&2
    exit 1
  fi

  "${COMPOSE_CMD[@]}" up -d

  if [[ "${WAIT_FOR_DOCS}" -eq 1 ]] && command -v curl >/dev/null 2>&1; then
    port="$(ENV_FILE="${ENV_FILE}" python3 - <<'PY'\nimport os\nfrom pathlib import Path\np = Path(os.environ['ENV_FILE'])\nport = '8081'\nif p.exists():\n  for line in p.read_text(encoding='utf-8').splitlines():\n    if line.startswith('PAYMENTS_API_PORT='):\n      port = line.split('=',1)[1].strip() or port\nprint(port)\nPY\n)"
    echo "Waiting for http://localhost:${port}/docs ..."
    for _ in $(seq 1 60); do
      if curl -fsS --max-time 2 "http://localhost:${port}/docs" >/dev/null 2>&1; then
        echo "OK: http://localhost:${port}/docs"
        break
      fi
      sleep 1
    done
  fi
fi

if [[ "${RUN_DEMO}" -eq 1 ]]; then
  if [[ -z "${RECIPIENT}" || -z "${AMOUNT_ETH}" || -z "${PRIVATE_KEY_FILE}" ]]; then
    echo "Demo requires --recipient, --amount-eth, and --private-key-file." >&2
    exit 2
  fi

  demo_args=(--recipient "${RECIPIENT}" --amount-eth "${AMOUNT_ETH}" --private-key-file "${PRIVATE_KEY_FILE}")
  [[ -n "${RPC_URL}" ]] && demo_args+=(--rpc-url "${RPC_URL}")
  [[ -n "${CHAIN_ID}" ]] && demo_args+=(--chain-id "${CHAIN_ID}")
  [[ -n "${TICKET_BROKER}" ]] && demo_args+=(--ticket-broker "${TICKET_BROKER}")
  [[ -n "${FUND_DEPOSIT_ETH}" ]] && demo_args+=(--fund-deposit-eth "${FUND_DEPOSIT_ETH}")
  [[ "${DEMO_WAIT}" -eq 1 ]] && demo_args+=(--wait)

  python3 scripts/livepeer_ticket_demo.py "${demo_args[@]}"
else
  cat <<'EOF'
Next steps (optional):
  - Run a demo redemption:
      python3 scripts/livepeer_ticket_demo.py --recipient 0x... --amount-eth 0.001 --wait
  - For Nitro/TEE, see:
      docs/security-review-tee.md
      docs/tee-core.md
      docs/tee-transparency.md
EOF
fi
