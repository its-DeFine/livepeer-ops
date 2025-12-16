#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  aws-create-snapshot.sh (--volume-id <vol-...> | --instance-id <i-...>) [--device-name </dev/...>] [--region <region>] [--name <snapshot-name>]

Creates an EBS snapshot for the given volume and tags it for easy discovery.
Requires: aws-cli configured with permission to create snapshots and tag resources.
EOF
}

VOLUME_ID=""
INSTANCE_ID=""
DEVICE_NAME="/dev/sda1"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-}}"
NAME=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --volume-id)
      VOLUME_ID="${2:-}"
      shift 2
      ;;
    --instance-id)
      INSTANCE_ID="${2:-}"
      shift 2
      ;;
    --device-name)
      DEVICE_NAME="${2:-}"
      shift 2
      ;;
    --region)
      REGION="${2:-}"
      shift 2
      ;;
    --name)
      NAME="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "$REGION" ]]; then
  echo "Missing --region (or AWS_REGION/AWS_DEFAULT_REGION)" >&2
  usage >&2
  exit 2
fi

if [[ -n "$VOLUME_ID" && -n "$INSTANCE_ID" ]]; then
  echo "Provide only one of --volume-id or --instance-id" >&2
  usage >&2
  exit 2
fi

if [[ -z "$VOLUME_ID" && -z "$INSTANCE_ID" ]]; then
  echo "Missing --volume-id or --instance-id" >&2
  usage >&2
  exit 2
fi

if [[ -z "$VOLUME_ID" ]]; then
  VOLUME_ID="$(
    aws ec2 describe-instances \
      --region "$REGION" \
      --instance-ids "$INSTANCE_ID" \
      --query "Reservations[0].Instances[0].BlockDeviceMappings[?DeviceName=='${DEVICE_NAME}'].Ebs.VolumeId | [0]" \
      --output text
  )"
  if [[ -z "$VOLUME_ID" || "$VOLUME_ID" == "None" ]]; then
    echo "Unable to resolve volume ID for instance $INSTANCE_ID (device $DEVICE_NAME)" >&2
    exit 1
  fi
fi

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
if [[ -z "$NAME" ]]; then
  NAME="payments-backend-${timestamp}"
fi

snapshot_id="$(
  aws ec2 create-snapshot \
    --region "$REGION" \
    --volume-id "$VOLUME_ID" \
    --description "$NAME" \
    --tag-specifications "ResourceType=snapshot,Tags=[{Key=Name,Value=$NAME},{Key=Service,Value=payments-backend},{Key=CreatedBy,Value=aws-create-snapshot.sh}]" \
    --query SnapshotId \
    --output text
)"

echo "Created snapshot: $snapshot_id"
echo "Region: $REGION"
