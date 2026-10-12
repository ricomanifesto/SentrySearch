#!/usr/bin/env bash
# Read-only inspection of the account and region a staging environment would
# use. It runs a fixed list of AWS CLI read commands with the profile you name,
# saves each answer to its own file and writes a manifest of what ran. It never
# creates, changes or deletes anything in the account.
#
#   aws-07a-inspect.sh --profile <profile> --region <region> [--out <directory>]
#   aws-07a-inspect.sh --list
#
# See README.md beside this script.
set -euo pipefail
umask 077

PRICING_ENDPOINT_REGION=us-east-1
NAME_PREFIX=sentry-staging

usage() {
  sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'
}

die() {
  printf 'aws-07a-inspect: %s\n' "$*" >&2
  exit 2
}

# The Price List location name for a region. Prices are skipped elsewhere.
price_location() {
  case "$1" in
    us-east-1) printf 'US East (N. Virginia)' ;;
    us-east-2) printf 'US East (Ohio)' ;;
    us-west-2) printf 'US West (Oregon)' ;;
    *) printf '' ;;
  esac
}

# ---------------------------------------------------------------------------
# The allowlist. Nothing else is ever sent. Each line is an output name and the
# exact AWS CLI arguments. `inspect` runs in the chosen region; `price` asks the
# Price List endpoint. ACCOUNT is the caller's account, read by the first
# command; LOCATION is the Price List name of the chosen region.
# ---------------------------------------------------------------------------
# JMESPath literals are written in backticks, which must reach the CLI as typed.
# shellcheck disable=SC2016
commands() {
  inspect 01-sts-caller-identity sts get-caller-identity
  inspect 02-ec2-availability-zones ec2 describe-availability-zones \
    --filters Name=state,Values=available --query 'AvailabilityZones[].ZoneName'
  inspect 03-rds-postgres-16-versions rds describe-db-engine-versions --engine postgres \
    --query 'DBEngineVersions[?starts_with(EngineVersion, `16.`)].EngineVersion'
  inspect 04-rds-orderable-t4g-micro rds describe-orderable-db-instance-options \
    --engine postgres --db-instance-class db.t4g.micro \
    --query 'OrderableDBInstanceOptions[?starts_with(EngineVersion, `16.`)].[EngineVersion,StorageType,MultiAZCapable]'
  inspect 05-quotas-fargate service-quotas list-service-quotas --service-code fargate \
    --query 'Quotas[].[QuotaName,Value]'
  inspect 06-quotas-vpc-endpoints service-quotas list-service-quotas --service-code vpc \
    --query 'Quotas[?contains(QuotaName, `endpoint`)].[QuotaName,Value]'
  inspect 07-ec2-vpcs ec2 describe-vpcs --query 'Vpcs[].[VpcId,CidrBlock,IsDefault]'
  inspect 08-ecr-repositories ecr describe-repositories \
    --query "repositories[?starts_with(repositoryName, \`${NAME_PREFIX}/\`)].repositoryName"
  inspect 09-logs-log-groups logs describe-log-groups \
    --log-group-name-prefix "/${NAME_PREFIX}/" --query 'logGroups[].logGroupName'
  inspect 10-secretsmanager-secrets secretsmanager list-secrets \
    --filters "Key=name,Values=${NAME_PREFIX}/" --query 'SecretList[].Name'
  inspect 11-ecs-clusters ecs list-clusters
  inspect 12-iam-operator-role iam get-role --role-name "${NAME_PREFIX}-operator"
  inspect 13-budgets budgets describe-budgets --account-id "$ACCOUNT"
  price 14-price-vpc-endpoints pricing get-products --service-code AmazonVPC \
    --filters "Type=TERM_MATCH,Field=location,Value=${LOCATION}" \
    Type=TERM_MATCH,Field=productFamily,Value=VpcEndpoint
  price 15-price-rds-instance pricing get-products --service-code AmazonRDS \
    --filters "Type=TERM_MATCH,Field=location,Value=${LOCATION}" \
    Type=TERM_MATCH,Field=instanceType,Value=db.t4g.micro \
    Type=TERM_MATCH,Field=databaseEngine,Value=PostgreSQL \
    Type=TERM_MATCH,Field=deploymentOption,Value=Single-AZ
  price 16-price-rds-storage pricing get-products --service-code AmazonRDS \
    --filters "Type=TERM_MATCH,Field=location,Value=${LOCATION}" \
    'Type=TERM_MATCH,Field=productFamily,Value=Database Storage' \
    Type=TERM_MATCH,Field=deploymentOption,Value=Single-AZ
  price 17-price-fargate pricing get-products --service-code AmazonECS \
    --filters "Type=TERM_MATCH,Field=location,Value=${LOCATION}"
  price 18-price-secrets-manager pricing get-products --service-code AWSSecretsManager \
    --filters "Type=TERM_MATCH,Field=location,Value=${LOCATION}"
}

# Words that name a change. An operation containing one is refused, as is any
# operation that does not start with get-, describe- or list-.
MUTATING="create delete put update modify attach detach run start stop terminate \
register deregister tag untag set add remove associate disassociate enable disable \
authorize revoke import send publish invoke execute reboot restore apply cancel purchase \
accept reject replace reset rotate assume copy move upload sync change grant deny \
allocate release failover promote rollback migrate schedule submit upgrade downgrade"

# Arguments that could redirect a request, read a local file or weaken TLS.
FORBIDDEN_ARGUMENTS="--endpoint-url --no-verify-ssl --no-sign-request --cli-input-json \
--cli-input-yaml --generate-cli-skeleton --profile --region --debug --ca-bundle"

command_text() {
  local text="aws" argument
  for argument in "$@"; do
    text+=" $(printf '%q' "$argument")"
  done
  printf '%s' "$text"
}

# Exits unless "<service> <operation> [arguments]" is a read.
require_read_only() {
  local service=$1 operation=$2 word argument
  shift 2
  [[ $service =~ ^[a-z0-9-]+$ ]] || die "refusing: not a service name: $service"
  [[ $operation =~ ^(get|describe|list)-[a-z0-9-]+$ ]] ||
    die "refusing: not a read operation: $service $operation"
  for word in ${operation//-/ }; do
    case " $MUTATING " in
      *" $word "*) die "refusing: mutating verb '$word' in: $service $operation" ;;
    esac
  done
  for argument in "$@"; do
    case " $FORBIDDEN_ARGUMENTS " in
      *" $argument "*) die "refusing: argument $argument in: $service $operation" ;;
    esac
    case "$argument" in
      *file://* | *fileb://* | *http://* | *https://*)
        die "refusing: a file or URL argument in: $service $operation"
        ;;
    esac
  done
}

sha256() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d' ' -f1
  else
    sha256sum "$1" | cut -d' ' -f1
  fi
}

json_string() {
  local value=$1
  value=${value//\\/\\\\}
  value=${value//\"/\\\"}
  printf '"%s"' "$value"
}

# --- Pass one: check every allowlisted command, sending nothing ---------------
LISTED=()
check() {
  local name=$1
  shift
  [[ $name =~ ^[0-9]{2}-[a-z0-9-]+$ ]] || die "refusing: bad output name: $name"
  require_read_only "$@"
  LISTED+=("$name	$(command_text "$@")")
}
inspect() { check "$@"; }
price() { check "$@"; }

ACCOUNT=000000000000
LOCATION='<price list location>'
commands
[[ ${LISTED[0]} == 01-sts-caller-identity$'\t'* ]] || die "refusing: the identity check is not first"

PROFILE="" REGION="" OUT="" LIST=0
while (($#)); do
  case "$1" in
    --profile) PROFILE=${2-}; shift 2 || die "--profile needs a value" ;;
    --region) REGION=${2-}; shift 2 || die "--region needs a value" ;;
    --out) OUT=${2-}; shift 2 || die "--out needs a value" ;;
    --list) LIST=1; shift ;;
    -h | --help) usage; exit 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
done

if ((LIST)); then
  printf '%s\n' "${LISTED[@]}"
  exit 0
fi

[[ -n $PROFILE ]] || die "--profile is required: name the profile you authenticated"
[[ $PROFILE =~ ^[A-Za-z0-9_.@+=,-]+$ ]] || die "not a profile name: $PROFILE"
[[ $REGION =~ ^[a-z]{2}-[a-z]+-[0-9]$ ]] || die "--region is required: a commercial region such as us-east-1"
command -v aws >/dev/null 2>&1 || die "the AWS CLI is not on PATH"
OUT=${OUT:-"$HOME/Documents/Codex/$(date -u +%Y-%m-%d)/aws-07a-inspection"}
if [[ -e $OUT ]] && [[ -n $(ls -A "$OUT" 2>/dev/null) ]]; then
  die "refusing to write into a directory that is not empty: $OUT"
fi
mkdir -p "$OUT"
LOCATION=$(price_location "$REGION")

# --- Pass two: run them, in order, with only the named profile ---------------
ENTRIES=()
SKIPPED=()
execute() {
  local region=$1 name=$2 code=0
  shift 2
  local out="$OUT/$name.json" err="$OUT/$name.stderr.txt"
  # Only the named profile supplies credentials: nothing inherited can replace it.
  env -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY -u AWS_SESSION_TOKEN \
    -u AWS_PROFILE -u AWS_DEFAULT_PROFILE -u AWS_REGION -u AWS_DEFAULT_REGION \
    -u AWS_ENDPOINT_URL -u AWS_CA_BUNDLE AWS_PAGER="" \
    aws --profile "$PROFILE" --region "$region" --output json --no-cli-pager \
    --cli-connect-timeout 10 --cli-read-timeout 60 "$@" >"$out" 2>"$err" || code=$?
  ENTRIES+=("    {\"name\": $(json_string "$name"), \"command\": $(json_string "$(command_text "$@")"), \"region\": $(json_string "$region"), \"exit_code\": $code, \"stdout\": $(json_string "$name.json"), \"stdout_sha256\": \"$(sha256 "$out")\", \"stderr\": $(json_string "$name.stderr.txt"), \"stderr_sha256\": \"$(sha256 "$err")\"}")
  printf '  %-28s exit %s\n' "$name" "$code"
  return 0
}

write_manifest() {
  local index
  {
    printf '{\n'
    printf '  "kit": "aws-07a-inspect",\n'
    printf '  "kit_sha256": "%s",\n' "$(sha256 "$0")"
    printf '  "started_at": "%s",\n' "$STARTED"
    printf '  "finished_at": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '  "region": %s,\n' "$(json_string "$REGION")"
    printf '  "name_prefix": %s,\n' "$(json_string "$NAME_PREFIX")"
    printf '  "account_id": %s,\n' "$(json_string "$ACCOUNT")"
    printf '  "skipped": ['
    # Counted loops: an empty array is "unbound" to set -u in older bash.
    for ((index = 0; index < ${#SKIPPED[@]}; index++)); do
      if ((index)); then printf ', '; fi
      json_string "${SKIPPED[$index]}"
    done
    printf '],\n'
    printf '  "commands": [\n'
    for ((index = 0; index < ${#ENTRIES[@]}; index++)); do
      printf '%s' "${ENTRIES[$index]}"
      if ((index + 1 < ${#ENTRIES[@]})); then printf ','; fi
      printf '\n'
    done
    printf '  ]\n}\n'
  } >"$OUT/manifest.json"
}

inspect() {
  local name=$1
  shift
  require_read_only "$@"
  execute "$REGION" "$name" "$@"
  if [[ $name == 01-sts-caller-identity ]]; then
    ACCOUNT=$(sed -n 's/.*"Account": *"\([0-9]\{12\}\)".*/\1/p' "$OUT/$name.json" | head -n 1)
    if [[ -z $ACCOUNT ]]; then
      ACCOUNT=""
      write_manifest
      die "the caller's identity could not be read; nothing else was run. See $OUT/$name.stderr.txt"
    fi
  fi
}
price() {
  local name=$1
  shift
  require_read_only "$@"
  if [[ -z $LOCATION ]]; then
    SKIPPED+=("$name")
    return 0
  fi
  execute "$PRICING_ENDPOINT_REGION" "$name" "$@"
}

STARTED=$(date -u +%Y-%m-%dT%H:%M:%SZ)
ACCOUNT=""
printf 'Reading account and region facts (read-only) into %s\n' "$OUT"
commands
write_manifest
printf 'Done: %s commands, account %s, region %s.\n' "${#ENTRIES[@]}" "$ACCOUNT" "$REGION"
printf 'Bundle: %s (manifest.json lists every command, exit code and SHA-256)\n' "$OUT"
printf 'Nothing in the account was created, changed or deleted.\n'
