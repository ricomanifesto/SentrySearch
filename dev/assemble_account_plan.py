"""Turn a read-only inspection bundle into the staging roots' account inputs.

Offline and standard library only: no AWS call, credential, network or Terraform
run. It reads the bundle ``deploy/aws-staging/inspect/aws-07a-inspect.sh`` wrote
and a ``decisions.json`` of the environment values someone chose, and writes:

- ``<root>/account.auto.tfvars.json`` for bootstrap, foundation, releases and
  services, holding exactly the inputs known before anything is applied;
- ``manifest.skeleton.json``, a schema-2 release manifest with the account's
  identities filled in and every later value marked ``TBD(...)``;
- ``account-plan.json`` and ``account-plan.md``: the inspection checklist with
  each item met, unmet or unknown, the price table refreshed from the bundle's
  price records, the inputs still pending, and one hash over the plan (its inputs,
  skeleton, bundle and decisions hashes, and the checklist).

    python -m dev.assemble_account_plan verify   --bundle <dir>
    python -m dev.assemble_account_plan draft    --bundle <dir> --out decisions.json
    python -m dev.assemble_account_plan assemble --bundle <dir> --decisions decisions.json --out <dir>

A bundle whose files do not match its manifest is unusable and nothing is
written from it. ``--manifest-sha256`` takes the hash the kit printed when it
finished; with it, a manifest edited afterwards is refused. ``draft`` proposes
the values the inspection can suggest; the rest stay null for a person to fill
in. Nothing here decides anything.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sys
from typing import Any

ROOTS = ("bootstrap", "foundation", "releases", "services")
KIT = "aws-07a-inspect"
KIT_SCRIPT = Path(__file__).resolve().parents[1] / "deploy/aws-staging/inspect/aws-07a-inspect.sh"
# Each answer the kit saves and the read that produces it. An answer recorded
# under any other command is not that answer.
OPERATIONS = {
    "01-sts-caller-identity": "sts get-caller-identity",
    "02-ec2-availability-zones": "ec2 describe-availability-zones",
    "03-rds-postgres-16-versions": "rds describe-db-engine-versions",
    "04-rds-orderable-t4g-micro": "rds describe-orderable-db-instance-options",
    "05-quotas-fargate": "service-quotas list-service-quotas",
    "06-quotas-vpc-endpoints": "service-quotas list-service-quotas",
    "07-ec2-vpcs": "ec2 describe-vpcs",
    "08-ecr-repositories": "ecr describe-repositories",
    "09-logs-log-groups": "logs describe-log-groups",
    "10-secretsmanager-secrets": "secretsmanager list-secrets",
    "11-ecs-clusters": "ecs list-clusters",
    "12-iam-operator-role": "iam get-role",
    "13-budgets": "budgets describe-budgets",
    "14-price-vpc-endpoints": "pricing get-products",
    "15-price-rds-instance": "pricing get-products",
    "16-price-rds-storage": "pricing get-products",
    "17-price-fargate": "pricing get-products",
    "18-price-secrets-manager": "pricing get-products",
}
READS = tuple(name for name in OPERATIONS if "-price-" not in name)
PRICES = tuple(name for name in OPERATIONS if "-price-" in name)
HOURS = 730
# What the plan runs: three services (Runtime 0.25 vCPU/0.5 GiB, API 0.25/1,
# worker 0.5/2) and one 0.25 vCPU job or observer at a time.
SERVICE_VCPU, SERVICE_GB, JOB_VCPU = 1.0, 3.5, 0.25
INTERFACE_ENDPOINTS, ENDPOINT_ZONES, GATEWAY_ENDPOINTS = 4, 2, 1
DATABASES, STORAGE_GB = 2, 20
SECRETS = (13, 17)  # steady state, and with a first deployment's bootstrap bundles
# The estimate these prices are compared with: public us-east-1 on-demand rates
# as read on 2026-10-08. Hourly rates; storage and secrets are per month.
ESTIMATE_DATE = "2026-10-08"
ESTIMATE = {
    "fargate_vcpu_hour": 0.0000089944 * 3600,
    "fargate_gb_hour": 0.0000009889 * 3600,
    "endpoint_hour": 0.01,
    "rds_instance_hour": 0.016,
    "rds_storage_gb_month": 0.115,
    "secret_month": 0.40,
}
# Lines the bundle does not price: CloudWatch alarms and logs, and the small rest.
UNPRICED_MONTHLY = (0.50 + 1.0, 5.50 + 3.0)
# Proposed when nothing was chosen; each is checked against the account's VPCs.
CIDR_CANDIDATES = ("10.64.0.0/20", "10.96.0.0/20", "172.24.0.0/20", "192.168.64.0/20")


class Unusable(Exception):
    """The bundle or the decisions cannot be used as they are."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(document: Any) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()


# The bundle ------------------------------------------------------------------------


class Bundle:
    """A verified bundle: every file is the one its manifest hashed.

    The manifest itself is only as good as its own hash. ``printed`` is the hash
    the kit printed when it finished; without it nothing shows that the manifest
    was not rewritten afterwards, and the plan says so.
    """

    def __init__(self, root: Path, printed: str | None = None) -> None:
        self.root = root
        try:
            raw = (root / "manifest.json").read_bytes()
            manifest = json.loads(raw)
        except (OSError, ValueError):
            raise Unusable("the bundle has no readable manifest.json") from None
        if not isinstance(manifest, dict) or manifest.get("kit") != KIT:
            raise Unusable("manifest.json was not written by the inspection kit")
        self.manifest = manifest
        self.manifest_sha256 = sha256(raw)
        if printed is not None and printed != self.manifest_sha256:
            raise Unusable("manifest.json is not the one whose SHA-256 the kit printed")
        self.manifest_confirmed = printed is not None
        self.commands: dict[str, dict[str, Any]] = {}
        listed = {"manifest.json"}
        entries = manifest.get("commands")
        if not isinstance(entries, list) or not entries:
            raise Unusable("the manifest lists no commands")
        for entry in entries:
            name = entry.get("name") if isinstance(entry, dict) else None
            if not isinstance(name, str) or name in self.commands:
                raise Unusable("the manifest's command list is malformed")
            if name not in OPERATIONS:
                raise Unusable(f"{name} is not a command of the inspection kit")
            text = entry.get("command")
            read = f"aws {OPERATIONS[name]}"
            if not isinstance(text, str) or not (text == read or text.startswith(read + " ")):
                raise Unusable(f"{name} was not recorded as `{read}`")
            for stream in ("stdout", "stderr"):
                self._verify(entry, stream)
                listed.add(entry[stream])
            if not isinstance(entry.get("exit_code"), int) or isinstance(entry["exit_code"], bool):
                raise Unusable(f"{name}: no exit code")
            self.commands[name] = entry
        present = {path.name for path in root.iterdir()}
        if present != listed:
            raise Unusable(f"files the manifest does not list: {sorted(present - listed)}")
        if entries[0]["name"] != READS[0] or entries[0]["exit_code"] != 0:
            raise Unusable("the bundle does not start with a successful identity check")
        skipped = manifest.get("skipped", [])
        missing = [name for name in READS if name not in self.commands]
        missing += [name for name in PRICES if name not in self.commands and name not in skipped]
        if missing:
            raise Unusable(f"commands missing from the bundle: {missing}")
        identity = self.answer(READS[0])
        account = identity.get("Account") if isinstance(identity, dict) else None
        if not isinstance(account, str) or account != manifest.get("account_id"):
            raise Unusable("the identity answer and the manifest name different accounts")
        self.account_id: str = account
        self.region: str = str(manifest.get("region", ""))
        self.name_prefix: str = str(manifest.get("name_prefix", ""))

    def _verify(self, entry: dict[str, Any], stream: str) -> None:
        name, wanted = entry.get(stream), entry.get(f"{stream}_sha256")
        if not isinstance(name, str) or Path(name).name != name or name in {".", ".."}:
            raise Unusable("a manifest entry does not name a file in the bundle")
        path = self.root / name
        if path.is_symlink() or not path.is_file():
            raise Unusable(f"{name} is not a regular file in the bundle")
        if sha256(path.read_bytes()) != wanted:
            raise Unusable(f"{name} does not match the manifest's SHA-256")

    def answer(self, name: str) -> Any:
        """The command's parsed answer, or None if it failed, was skipped or is not JSON."""
        entry = self.commands.get(name)
        if entry is None or entry["exit_code"] != 0:
            return None
        try:
            return json.loads((self.root / entry["stdout"]).read_text())
        except ValueError:
            return None

    def error(self, name: str) -> str:
        entry = self.commands.get(name)
        return "" if entry is None else (self.root / entry["stderr"]).read_text()

    def kit_matches(self) -> bool | None:
        """Whether the kit that wrote the bundle is this checkout's; None if that is unreadable."""
        try:
            reviewed = sha256(KIT_SCRIPT.read_bytes())
        except OSError:
            return None
        return self.manifest.get("kit_sha256") == reviewed


# Decisions ---------------------------------------------------------------------------

DECISION_KEYS = {
    "account_id", "account_confirmed_by", "region", "name_prefix", "availability_zones",
    "vpc_cidr", "private_dns_namespace", "postgres_engine_version", "operator",
    "operator_trust", "notifications", "lifetime_days", "basis",
}  # fmt: skip
NAMESPACE = re.compile(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+")
PRIVATE = [ipaddress.ip_network(net) for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise Unusable(f"decisions.json: {message}")


def check_decisions(decisions: Any) -> dict[str, Any]:
    """The roots' own input rules, applied before anything is written."""
    _require(isinstance(decisions, dict), "not an object")
    _require(
        set(decisions) <= DECISION_KEYS, f"unknown keys {sorted(set(decisions) - DECISION_KEYS)}"
    )
    account, region = decisions.get("account_id"), decisions.get("region")
    prefix = decisions.get("name_prefix")
    _require(isinstance(account, str) and re.fullmatch(r"[0-9]{12}", account) is not None,
             "account_id is a 12-digit string")  # fmt: skip
    confirmed = decisions.get("account_confirmed_by")
    _require(confirmed is None or (isinstance(confirmed, str)
                                   and re.fullmatch(r"[A-Za-z0-9 .,@+=_-]{2,64}", confirmed)
                                   is not None),
             "account_confirmed_by is who confirmed the account, or null")  # fmt: skip
    _require(isinstance(region, str) and re.fullmatch(r"[a-z]{2}-[a-z]+-[0-9]", region) is not None,
             "region is a commercial region")  # fmt: skip
    _require(isinstance(prefix, str) and len(prefix) <= 28
             and re.fullmatch(r"[a-z][a-z0-9]*(-[a-z0-9]+)*-staging", prefix) is not None,
             "name_prefix ends in -staging, at most 28 characters")  # fmt: skip
    zones = decisions.get("availability_zones")
    _require(isinstance(zones, list) and len(zones) == 2 and len(set(zones)) == 2
             and all(isinstance(z, str) and re.fullmatch(re.escape(region) + "[a-z]", z)
                     for z in zones),
             "availability_zones are two distinct zones of the region")  # fmt: skip
    cidr = decisions.get("vpc_cidr")
    try:
        network = ipaddress.ip_network(cidr, strict=True) if isinstance(cidr, str) else None
    except ValueError:
        network = None
    _require(network is not None and network.version == 4 and 16 <= network.prefixlen <= 24
             and any(network.subnet_of(private) for private in PRIVATE),  # type: ignore[arg-type]
             "vpc_cidr is an aligned RFC 1918 network between /16 and /24")  # fmt: skip
    namespace = decisions.get("private_dns_namespace")
    _require(isinstance(namespace, str) and len(namespace) <= 200
             and NAMESPACE.fullmatch(namespace) is not None
             and re.fullmatch(r"[0-9.]+", namespace) is None,
             "private_dns_namespace is a lowercase multi-label name")  # fmt: skip
    version = decisions.get("postgres_engine_version")
    _require(isinstance(version, str) and re.fullmatch(r"16\.[0-9]+", version) is not None,
             "postgres_engine_version is an exact 16.x minor")  # fmt: skip
    operator = decisions.get("operator")
    _require(operator is None or (isinstance(operator, str)
                                  and re.fullmatch(r"[A-Za-z0-9+=,.@-]{2,64}", operator) is not None),
             "operator is a valid role-session name or null")  # fmt: skip
    trust = decisions.get("operator_trust")
    if trust is not None:
        _require(isinstance(trust, dict)
                 and set(trust) == {"principal_arn", "external_id", "session_seconds"},
                 "operator_trust has principal_arn, external_id and session_seconds")  # fmt: skip
        _require(operator is not None, "operator_trust needs an operator")
        arn, external, seconds = (
            trust["principal_arn"],
            trust["external_id"],
            trust["session_seconds"],
        )
        _require(isinstance(arn, str) and "*" not in arn and re.fullmatch(
            r"arn:aws:iam::[0-9]{12}:(user|role)/[A-Za-z0-9+=,.@_/-]{1,512}", arn) is not None,
            "operator_trust.principal_arn is one IAM user or role")  # fmt: skip
        _require(isinstance(external, str) and 16 <= len(external) <= 1224
                 and re.fullmatch(r"[A-Za-z0-9+=,.@:/-]+", external) is not None,
                 "operator_trust.external_id is 16 to 1224 allowed characters")  # fmt: skip
        _require(isinstance(seconds, int) and not isinstance(seconds, bool)
                 and 3600 <= seconds <= 43200,
                 "operator_trust.session_seconds is one to twelve hours")  # fmt: skip
    notify = decisions.get("notifications")
    if notify is not None:
        _require(isinstance(notify, dict) and set(notify) == {"email", "monthly_budget_usd"},
                 "notifications has email and monthly_budget_usd")  # fmt: skip
        email, budget = notify["email"], notify["monthly_budget_usd"]
        _require(isinstance(email, str) and re.fullmatch(
            r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", email) is not None,
            "notifications.email is one address")  # fmt: skip
        _require(isinstance(budget, int) and not isinstance(budget, bool) and 0 < budget <= 10000,
                 "notifications.monthly_budget_usd is whole dollars up to 10000")  # fmt: skip
    days = decisions.get("lifetime_days", 7)
    _require(isinstance(days, int) and not isinstance(days, bool) and 1 <= days <= 90,
             "lifetime_days is 1 to 90")  # fmt: skip
    return decisions


# What the bundle says ----------------------------------------------------------------


def _strings(value: Any) -> list[str] | None:
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    return None


def _minor(version: str) -> int:
    return int(version.split(".")[1])


def gp3_versions(bundle: Bundle) -> list[str] | None:
    """PostgreSQL 16 minors orderable on db.t4g.micro with gp3, lowest first."""
    rows = bundle.answer("04-rds-orderable-t4g-micro")
    if not isinstance(rows, list):
        return None
    found = {row[0] for row in rows
             if isinstance(row, list) and len(row) == 3 and row[1] == "gp3"
             and isinstance(row[0], str) and re.fullmatch(r"16\.[0-9]+", row[0])}  # fmt: skip
    return sorted(found, key=_minor)


def existing_vpcs(bundle: Bundle) -> list[ipaddress.IPv4Network] | None:
    """Every IPv4 range of every VPC: the primary one and each one associated later."""
    rows = bundle.answer("07-ec2-vpcs")
    if not isinstance(rows, list):
        return None
    networks = set()
    for row in rows:
        if not isinstance(row, list) or len(row) != 4 or not isinstance(row[3], (list, type(None))):
            return None
        try:
            for block in (row[1], *(row[3] or [])):
                networks.add(ipaddress.ip_network(block, strict=False))
        except (TypeError, ValueError):
            return None
    return sorted((network for network in networks
                   if isinstance(network, ipaddress.IPv4Network)), key=str)  # fmt: skip


def _quota(rows: Any, words: tuple[str, ...]) -> float | None:
    if not isinstance(rows, list):
        return None
    values = [row[1] for row in rows
              if isinstance(row, list) and len(row) == 2 and isinstance(row[0], str)
              and all(word in row[0] for word in words)
              and isinstance(row[1], (int, float)) and not isinstance(row[1], bool)]  # fmt: skip
    return values[0] if len(values) == 1 else None


def _item(key: str, text: str, status: str, evidence: str, *sources: str) -> dict[str, Any]:
    return {"id": key, "check": text, "status": status, "evidence": evidence,
            "sources": [f"{name}.json" for name in sources]}  # fmt: skip


def _absent(key: str, text: str, found: list[str] | None, source: str) -> dict[str, Any]:
    if found is None:
        return _item(key, text, "unknown", "the answer is missing or unreadable", source)
    status = "met" if not found else "unmet"
    return _item(
        key, text, status, "none found" if not found else f"found: {sorted(found)}", source
    )


def checklist(
    bundle: Bundle, decisions: dict[str, Any], prices: dict[str, Any]
) -> list[dict[str, Any]]:
    """The inspection's checks, each met, unmet or unknown with what was seen."""
    prefix = decisions["name_prefix"]
    text = "The bundle was written by this checkout's inspection kit"
    kit = bundle.kit_matches()
    recorded = f"the manifest records kit {bundle.manifest.get('kit_sha256')}"
    if kit is None:
        items = [_item("kit", text, "unknown", "this checkout's kit could not be read")]
    else:
        items = [_item("kit", text, "met" if kit else "unmet",
                       recorded + ("" if kit else ", which is not this checkout's"))]  # fmt: skip
    text = "The manifest is the one the kit printed"
    if bundle.manifest_confirmed:
        items.append(_item("manifest", text, "met", f"SHA-256 {bundle.manifest_sha256}"))
    else:
        items.append(_item("manifest", text, "unknown",
                           "the SHA-256 the kit printed was not given to compare"))  # fmt: skip
    # The inspected account always equals the one in the decisions. Whether it is
    # the intended one is a person's statement, never something the bundle shows.
    confirmed = decisions.get("account_confirmed_by")
    text = "The identity is the intended account"
    if confirmed is None:
        items.append(_item("identity", text, "unknown",
                           f"account {bundle.account_id} was inspected; nobody has confirmed it",
                           READS[0]))  # fmt: skip
    else:
        items.append(_item("identity", text, "met",
                           f"account {bundle.account_id}, confirmed by {confirmed}", READS[0]))  # fmt: skip

    zones = _strings(bundle.answer("02-ec2-availability-zones"))
    chosen = decisions["availability_zones"]
    if zones is None:
        items.append(_item("zones", "Two zones are available", "unknown",
                           "the answer is missing or unreadable", "02-ec2-availability-zones"))  # fmt: skip
    else:
        ok = len(set(zones)) >= 2 and set(chosen) <= set(zones)
        items.append(_item("zones", "Two zones are available", "met" if ok else "unmet",
                           f"available {sorted(zones)}; chosen {chosen}",
                           "02-ec2-availability-zones"))  # fmt: skip

    versions = gp3_versions(bundle)
    text = "A PostgreSQL 16.x supports db.t4g.micro with gp3"
    if versions is None:
        items.append(_item("postgres", text, "unknown", "the answer is missing or unreadable",
                           "04-rds-orderable-t4g-micro"))  # fmt: skip
    else:
        ok = decisions["postgres_engine_version"] in versions
        items.append(_item("postgres", text, "met" if ok else "unmet",
                           f"orderable with gp3: {versions}; chosen "
                           f"{decisions['postgres_engine_version']}",
                           "03-rds-postgres-16-versions", "04-rds-orderable-t4g-micro"))  # fmt: skip

    needed = SERVICE_VCPU + JOB_VCPU
    vcpu = _quota(bundle.answer("05-quotas-fargate"), ("On-Demand", "vCPU"))
    text = "The Fargate quota covers the plan"
    if vcpu is None:
        items.append(_item("fargate_quota", text, "unknown",
                           "no single On-Demand vCPU quota in the answer", "05-quotas-fargate"))  # fmt: skip
    else:
        items.append(_item("fargate_quota", text, "met" if vcpu >= needed else "unmet",
                           f"quota {vcpu:g} vCPU; the plan needs {needed:g}", "05-quotas-fargate"))  # fmt: skip
    rows = bundle.answer("06-quotas-vpc-endpoints")
    interface = _quota(rows, ("Interface", "per VPC"))
    gateway = _quota(rows, ("Gateway", "per Region"))
    text = "The endpoint quotas cover the plan"
    if interface is None or gateway is None:
        items.append(_item("endpoint_quota", text, "unknown",
                           "interface or gateway endpoint quota not found in the answer",
                           "06-quotas-vpc-endpoints"))  # fmt: skip
    else:
        ok = interface >= INTERFACE_ENDPOINTS and gateway >= GATEWAY_ENDPOINTS
        items.append(_item("endpoint_quota", text, "met" if ok else "unmet",
                           f"interface per VPC {interface:g} (needs {INTERFACE_ENDPOINTS}); "
                           f"gateway per Region {gateway:g} (needs {GATEWAY_ENDPOINTS})",
                           "06-quotas-vpc-endpoints"))  # fmt: skip

    vpcs = existing_vpcs(bundle)
    text = "The planned VPC range overlaps no existing VPC"
    if vpcs is None:
        items.append(_item("vpc_range", text, "unknown", "the answer is missing or unreadable",
                           "07-ec2-vpcs"))  # fmt: skip
    else:
        planned = ipaddress.ip_network(decisions["vpc_cidr"])
        clash = sorted(str(network) for network in vpcs if network.overlaps(planned))
        items.append(_item("vpc_range", text, "unmet" if clash else "met",
                           f"planned {planned}; " + (f"overlaps {clash}" if clash else
                                                     f"{len(vpcs)} existing ranges, none "
                                                     "overlapping"),
                           "07-ec2-vpcs"))  # fmt: skip

    # The kit looked for its own prefix: another prefix was not inspected.
    same = prefix == bundle.name_prefix
    clusters = bundle.answer("11-ecs-clusters")
    arns = _strings(clusters.get("clusterArns")) if isinstance(clusters, dict) else None
    for key, label, found, source in (
        ("repositories", "repositories", _strings(bundle.answer("08-ecr-repositories")),
         "08-ecr-repositories"),
        ("log_groups", "log groups", _strings(bundle.answer("09-logs-log-groups")),
         "09-logs-log-groups"),
        ("secrets", "secrets", _strings(bundle.answer("10-secretsmanager-secrets")),
         "10-secretsmanager-secrets"),
        ("cluster", "cluster",
         None if arns is None else [arn for arn in arns if arn.endswith(f":cluster/{prefix}")],
         "11-ecs-clusters"),
    ):  # fmt: skip
        items.append(
            _absent(key, f"No {prefix} {label} exist yet", found if same else None, source)
        )
    role = bundle.commands["12-iam-operator-role"]
    text = "No operator role exists yet"
    if not same:
        status, evidence = "unknown", f"the bundle inspected {bundle.name_prefix}, not {prefix}"
    elif role["exit_code"] == 0:
        status, evidence = "unmet", f"{prefix}-operator already exists"
    elif "NoSuchEntity" in bundle.error("12-iam-operator-role"):
        status, evidence = "met", "IAM answered NoSuchEntity"
    else:
        status, evidence = (
            "unknown",
            f"the lookup failed (exit {role['exit_code']}) for another reason",
        )
    items.append(_item("operator_role", text, status, evidence, "12-iam-operator-role"))

    text = "The refreshed prices match the estimate, or the estimate is revised"
    if prices["unknown"]:
        items.append(_item("prices", text, "unknown",
                           f"no usable price record for: {prices['unknown']}", *PRICES))  # fmt: skip
    elif prices["changed"]:
        items.append(_item("prices", text, "met",
                           f"estimate revised for: {prices['changed']}; see the price table",
                           *PRICES))  # fmt: skip
    else:
        items.append(_item("prices", text, "met", "every refreshed rate equals the estimate's",
                           *PRICES))  # fmt: skip
    return items


# Prices ------------------------------------------------------------------------------

# rate -> (bundle command, usage-type ending, unit as the Price List names it)
PRICE_SOURCES = {
    "fargate_vcpu_hour": ("17-price-fargate", "Fargate-ARM-vCPU-Hours:perCPU", "hours"),
    "fargate_gb_hour": ("17-price-fargate", "Fargate-ARM-GB-Hours", "hours"),
    "endpoint_hour": ("14-price-vpc-endpoints", "VpcEndpoint-Hours", "hrs"),
    "rds_instance_hour": ("15-price-rds-instance", "InstanceUsage:db.t4g.micro", "hrs"),
    "rds_storage_gb_month": ("16-price-rds-storage", "RDS:GP3-Storage", "gb-mo"),
    "secret_month": ("18-price-secrets-manager", "AWSSecretsManager-Secrets", "secrets"),
}


def _usd(product: Any, ending: str, unit: str) -> list[float]:
    """Every on-demand USD price of a product whose usage type ends as given."""
    if isinstance(product, str):
        try:
            product = json.loads(product)
        except ValueError:
            return []
    try:
        if not product["product"]["attributes"]["usagetype"].endswith(ending):
            return []
        found = []
        for term in product["terms"]["OnDemand"].values():
            for dimension in term["priceDimensions"].values():
                if dimension["unit"].lower() == unit:
                    found.append(float(dimension["pricePerUnit"]["USD"]))
        return found
    except (KeyError, TypeError, ValueError, AttributeError):
        return []


def refreshed_prices(bundle: Bundle) -> dict[str, Any]:
    """The estimate's rates beside the bundle's, and the monthly cost under each."""
    rates: dict[str, dict[str, Any]] = {}
    for rate, (command, ending, unit) in PRICE_SOURCES.items():
        answer = bundle.answer(command)
        records = answer.get("PriceList") if isinstance(answer, dict) else None
        found = sorted({price for record in records or [] for price in _usd(record, ending, unit)})
        # One positive price is an answer; none or several is not.
        value = found[0] if len(found) == 1 and found[0] > 0 else None
        estimate = ESTIMATE[rate]
        rates[rate] = {
            "estimate": round(estimate, 10),
            "bundle": value,
            "status": ("unknown" if value is None
                       else "unchanged" if abs(value - estimate) <= estimate * 0.005
                       else "changed"),
            "source": f"{command}.json",
        }  # fmt: skip

    def monthly(use: dict[str, float]) -> dict[str, float]:
        fargate = (
            SERVICE_VCPU * use["fargate_vcpu_hour"] + SERVICE_GB * use["fargate_gb_hour"]
        ) * HOURS
        endpoints = INTERFACE_ENDPOINTS * ENDPOINT_ZONES * use["endpoint_hour"] * HOURS
        rds = DATABASES * (
            use["rds_instance_hour"] * HOURS + STORAGE_GB * use["rds_storage_gb_month"]
        )
        low = fargate + endpoints + rds + SECRETS[0] * use["secret_month"] + UNPRICED_MONTHLY[0]
        high = fargate + endpoints + rds + SECRETS[1] * use["secret_month"] + UNPRICED_MONTHLY[1]
        return {"fargate": round(fargate, 2), "endpoints": round(endpoints, 2), "rds": round(rds, 2),
                "secrets_low": round(SECRETS[0] * use["secret_month"], 2),
                "secrets_high": round(SECRETS[1] * use["secret_month"], 2),
                "unpriced_low": UNPRICED_MONTHLY[0], "unpriced_high": UNPRICED_MONTHLY[1],
                "total_low": round(low, 2), "total_high": round(high, 2)}  # fmt: skip

    current = {rate: (entry["bundle"] if entry["bundle"] is not None else entry["estimate"])
               for rate, entry in rates.items()}  # fmt: skip
    return {
        "estimate_date": ESTIMATE_DATE,
        "rates": rates,
        "monthly_estimate": monthly(ESTIMATE),
        # A rate the bundle could not supply keeps the estimate's value here.
        "monthly_refreshed": monthly(current),
        "unknown": sorted(rate for rate, entry in rates.items() if entry["status"] == "unknown"),
        "changed": sorted(rate for rate, entry in rates.items() if entry["status"] == "changed"),
    }


# Outputs -----------------------------------------------------------------------------


def draft(bundle: Bundle) -> dict[str, Any]:
    """Decisions the inspection can suggest; the rest stay null for a person."""
    zones = sorted(set(_strings(bundle.answer("02-ec2-availability-zones")) or []))
    versions = gp3_versions(bundle) or []
    vpcs = existing_vpcs(bundle)
    free = [cidr for cidr in CIDR_CANDIDATES
            if vpcs is not None
            and not any(net.overlaps(ipaddress.ip_network(cidr)) for net in vpcs)]  # fmt: skip
    return {
        "account_id": bundle.account_id,
        "account_confirmed_by": None,
        "region": bundle.region,
        "name_prefix": bundle.name_prefix,
        "availability_zones": zones[:2] if len(zones) >= 2 else None,
        "vpc_cidr": free[0] if free else None,
        "private_dns_namespace": f"{bundle.name_prefix}.internal",
        "postgres_engine_version": versions[-1] if versions else None,
        "operator": None,
        "operator_trust": None,
        "notifications": None,
        "lifetime_days": 7,
        "basis": {
            "account_id": "the inspected account",
            "account_confirmed_by": "whoever confirms this is the intended account",
            "region": "the inspected region",
            "name_prefix": "proposal default", "availability_zones": "first two available",
            "vpc_cidr": "first candidate overlapping no existing VPC",
            "private_dns_namespace": "proposal default",
            "postgres_engine_version": "highest 16.x orderable with gp3",
            "operator": "to be named", "operator_trust": "to be named",
            "notifications": "recipient to be named; the proposal's threshold is 200",
            "lifetime_days": "proposal default",
        },  # fmt: skip
    }


def root_inputs(
    decisions: dict[str, Any],
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, str]]]:
    """Each root's inputs known now, and the ones something later produces."""
    common = {key: decisions[key] for key in ("account_id", "region", "name_prefix")}
    namespace = decisions["private_dns_namespace"]
    inputs: dict[str, dict[str, Any]] = {
        "bootstrap": dict(common),
        "foundation": {**common, "availability_zones": decisions["availability_zones"],
                       "vpc_cidr": decisions["vpc_cidr"], "private_dns_namespace": namespace,
                       "postgres_engine_version": decisions["postgres_engine_version"]},
        "releases": {**common, "private_dns_namespace": namespace},
        "services": dict(common),
    }  # fmt: skip
    pending: dict[str, dict[str, str]] = {
        "bootstrap": {},
        "foundation": {},
        "releases": {
            "releases": "pushed image digests, the custodian's secret ARNs and version IDs, "
                        "and the release-tools digests",
            "observer_security_group_ids": "the foundation's runtime_transport_proof and "
                                           "api_proof groups",
        },
        "services": {
            "task_subnet_ids": "the foundation's private task subnets",
            "security_group_ids": "the foundation's per-service groups",
            "discovery_service_arns": "the foundation's Cloud Map services",
            "task_definition_arns": "the releases root's current revisions",
        },
    }  # fmt: skip
    trust = decisions.get("operator_trust")
    if trust is None:
        pending["bootstrap"][
            "operator_trust"
        ] = "the operator's issuing principal, a fresh external id and a session length"
    else:
        inputs["bootstrap"]["operator_trust"] = {**trust, "operator": decisions["operator"]}
    if decisions.get("notifications") is None:
        pending["foundation"][
            "notifications"
        ] = "an approved recipient and monthly review threshold"
    else:
        inputs["foundation"]["notifications"] = decisions["notifications"]
    return inputs, pending


def manifest_skeleton(decisions: dict[str, Any]) -> dict[str, Any]:
    """A schema-2 first-deployment manifest: identities filled in, the rest marked."""
    account, region, prefix = (decisions[key] for key in ("account_id", "region", "name_prefix"))
    ecs = f"arn:aws:ecs:{region}:{account}"

    def later(what: str) -> str:
        return f"TBD({what})"

    return {
        "schema_version": 2,
        "purpose": {"kind": "forward"},
        "release_id": later("a new release UUID"),
        "milestone": "operational-paused",
        "environment": {
            "name": prefix, "account_id": account, "region": region,
            "cluster_arn": f"{ecs}:cluster/{prefix}",
            "services": {name: f"{ecs}:service/{prefix}/{prefix}-{name}"
                         for name in ("runtime", "api", "worker")},
        },  # fmt: skip
        "operator": decisions.get("operator") or later("the named operator"),
        "operator_role": f"arn:aws:iam::{account}:role/{prefix}-operator",
        "window": later("the approved release window"),
        "sources": later("the accepted source commits"),
        "images": later("the pushed digests with their provenance, SBOM and scan hashes"),
        "risk": later("the recorded risk decision"),
        "plan_sha256": later("the reviewed Terraform plan's hash"),
        "network": {"subnets": later("the foundation's task subnets"),
                    "assign_public_ip": "DISABLED", "platform_version": "1.4.0"},  # fmt: skip
        "services": later("the releases root's service bindings"),
        "jobs": later("bootstrap, migrate, grant and proof jobs from the releases root's bindings"),
        "operational_checks": later("worker-readiness and both observers from the releases root"),
        "rollback": {"kind": "empty_hold"},
    }


def assemble(bundle: Bundle, decisions: dict[str, Any]) -> dict[str, Any]:
    check_decisions(decisions)
    if decisions["account_id"] != bundle.account_id:
        raise Unusable("the bundle inspected another account than decisions.json names")
    if decisions["region"] != bundle.region:
        raise Unusable("the bundle inspected another region than decisions.json names")
    prices = refreshed_prices(bundle)
    inputs, pending = root_inputs(decisions)
    skeleton = manifest_skeleton(decisions)
    items = checklist(bundle, decisions, prices)
    days = decisions.get("lifetime_days", 7)
    refreshed = prices["monthly_refreshed"]
    # The checklist is hashed too: a kit that runs only on an all-met inspection
    # must not be talked past it by an edited status.
    hashed = {"inputs": inputs, "manifest_skeleton": skeleton,
              "bundle_manifest_sha256": bundle.manifest_sha256,
              "decisions_sha256": sha256(canonical(decisions)), "checklist": items}  # fmt: skip
    return {
        "plan_sha256": sha256(canonical(hashed)),
        "bundle": {"manifest_sha256": bundle.manifest_sha256, "account_id": bundle.account_id,
                   "region": bundle.region, "kit_sha256": bundle.manifest.get("kit_sha256"),
                   "finished_at": bundle.manifest.get("finished_at"),
                   "skipped": bundle.manifest.get("skipped", [])},  # fmt: skip
        "decisions_sha256": hashed["decisions_sha256"],
        "inputs": inputs,
        "pending_inputs": pending,
        "manifest_skeleton": skeleton,
        "checklist": items,
        "prices": prices,
        "lifetime": {"days": days,
                     "cost_low": round(refreshed["total_low"] * days * 24 / HOURS, 2),
                     "cost_high": round(refreshed["total_high"] * days * 24 / HOURS, 2)},  # fmt: skip
    }


def render(plan: dict[str, Any]) -> str:
    """The plan as a page a person can read; account-plan.json is the record."""
    bundle, prices = plan["bundle"], plan["prices"]
    lines = [
        "# Account plan from the read-only inspection", "",
        f"- Plan hash: `{plan['plan_sha256']}`",
        f"- Account `{bundle['account_id']}`, region `{bundle['region']}`, inspected "
        f"{bundle['finished_at']}",
        f"- Bundle manifest SHA-256: `{bundle['manifest_sha256']}`",
        f"- Decisions SHA-256: `{plan['decisions_sha256']}`", "",
        "## Inspection checklist", "", "| Check | Status | Seen |", "| --- | --- | --- |",
    ]  # fmt: skip
    lines += [f"| {item['check']} | {item['status']} | {item['evidence']} |"
              for item in plan["checklist"]]  # fmt: skip
    lines += ["", f"## Prices (estimate of {prices['estimate_date']} beside the bundle)", "",
              "| Rate | Estimate | Bundle | Status |", "| --- | --- | --- | --- |"]  # fmt: skip
    for rate, entry in prices["rates"].items():
        seen = "none" if entry["bundle"] is None else f"{entry['bundle']:.6f}"
        lines.append(f"| {rate} | {entry['estimate']:.6f} | {seen} | {entry['status']} |")
    old, new, life = prices["monthly_estimate"], prices["monthly_refreshed"], plan["lifetime"]
    lines += [
        "", "| Monthly (USD) | Estimate | Refreshed |", "| --- | --- | --- |",
        f"| Fargate services | {old['fargate']:.2f} | {new['fargate']:.2f} |",
        f"| Interface endpoints | {old['endpoints']:.2f} | {new['endpoints']:.2f} |",
        f"| Two databases | {old['rds']:.2f} | {new['rds']:.2f} |",
        f"| Secrets | {old['secrets_low']:.2f} to {old['secrets_high']:.2f} | "
        f"{new['secrets_low']:.2f} to {new['secrets_high']:.2f} |",
        f"| Not priced by the bundle (CloudWatch and small items) | {old['unpriced_low']:.2f} to "
        f"{old['unpriced_high']:.2f} | same |",
        f"| **Total** | {old['total_low']:.2f} to {old['total_high']:.2f} | "
        f"{new['total_low']:.2f} to {new['total_high']:.2f} |", "",
        f"Over {life['days']} days: about {life['cost_low']:.2f} to {life['cost_high']:.2f} USD. "
        "An estimate, not a quote; a rate the bundle could not supply keeps the estimate's value.",
        "", "## Inputs still pending", "",
    ]  # fmt: skip
    for root in ROOTS:
        for name, source in plan["pending_inputs"][root].items():
            lines.append(f"- `{root}` `{name}`: {source}")
    return "\n".join(lines) + "\n"


def write_outputs(plan: dict[str, Any], out: Path) -> None:
    if out.exists() and any(out.iterdir()):
        raise Unusable(f"refusing to write into a directory that is not empty: {out}")
    out.mkdir(parents=True, exist_ok=True)
    for root in ROOTS:
        (out / root).mkdir()
        (out / root / "account.auto.tfvars.json").write_text(
            json.dumps(plan["inputs"][root], indent=2, sort_keys=True) + "\n"
        )
    (out / "manifest.skeleton.json").write_text(
        json.dumps(plan["manifest_skeleton"], indent=2) + "\n"
    )
    (out / "account-plan.json").write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n")
    (out / "account-plan.md").write_text(render(plan))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("verify", "draft", "assemble"):
        command = commands.add_parser(name)
        command.add_argument("--bundle", type=Path, required=True)
        command.add_argument("--manifest-sha256", help="the hash the kit printed at the end")
        if name != "verify":
            command.add_argument("--out", type=Path, required=True)
        if name == "assemble":
            command.add_argument("--decisions", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        bundle = Bundle(args.bundle, args.manifest_sha256)
        if args.command == "verify":
            kit = {True: "this checkout's", False: "NOT this checkout's", None: "unreadable here"}
            print(f"bundle verified: {len(bundle.commands)} commands, account {bundle.account_id}, "
                  f"region {bundle.region}, manifest {bundle.manifest_sha256}"
                  f"{'' if bundle.manifest_confirmed else ' (not compared with the kit output)'}, "
                  f"kit {kit[bundle.kit_matches()]}")  # fmt: skip
        elif args.command == "draft":
            if args.out.exists():
                raise Unusable(f"refusing to overwrite {args.out}")
            args.out.write_text(json.dumps(draft(bundle), indent=2) + "\n")
            print(f"draft written: {args.out}; null values need a person")
        else:
            try:
                decisions = json.loads(args.decisions.read_text())
            except (OSError, ValueError):
                raise Unusable("decisions.json is missing or not JSON") from None
            plan = assemble(bundle, decisions)
            write_outputs(plan, args.out)
            states = [item["status"] for item in plan["checklist"]]
            print(f"plan {plan['plan_sha256']}: {states.count('met')} met, "
                  f"{states.count('unmet')} unmet, {states.count('unknown')} unknown; "
                  f"written to {args.out}")  # fmt: skip
    except Unusable as error:
        print(f"assemble_account_plan: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
