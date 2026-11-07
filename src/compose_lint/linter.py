"""Core linting engine and AST inspection for Docker Compose files."""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

import yaml
from compose_lint.errors import ComposeLintError

logger = logging.getLogger(__name__)

KNOWN_RULES = {
    "CL001": "privileged: true container",
    "CL002": "docker.sock volume mounted",
    "CL003": "image without tag, :latest tag, or missing digest",
    "CL004": "published port without host IP binding",
    "CL005": "plaintext secret or credential in environment",
    "CL006": "network_mode: host",
    "CL007": "depends_on undefined service",
    "CL008": "duplicate mapping key",
    "CL009": "obsolete top-level version key",
    "CL010": "cap_add ALL or SYS_ADMIN",
}

SECRET_KEY_PATTERN = re.compile(r"(?i)(PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)")


@dataclass(frozen=True)
class Finding:
    """Represents a lint rule violation."""

    rule: str
    severity: Literal["error", "warning"]
    service: str | None
    line: int
    message: str


def _node_line(node: Node) -> int:
    """Return 1-based start line of a YAML node."""
    return int(node.start_mark.line) + 1


def _parse_yaml_tree(
    text: str,
    filename: str,
    max_bytes: int,
    max_nodes: int,
    max_depth: int,
) -> tuple[Node | None, list[Finding]]:
    encoded = text.encode("utf-8")
    if len(encoded) > max_bytes:
        raise ComposeLintError(
            "input_too_large",
            f"Input size {len(encoded)} bytes exceeds maximum {max_bytes} bytes",
        )

    loader = yaml.SafeLoader(text)
    loader.name = filename

    try:
        root = loader.get_single_node()
    except yaml.YAMLError as exc:
        line = 1
        if hasattr(exc, "problem_mark") and exc.problem_mark:
            line = exc.problem_mark.line + 1
        raise ComposeLintError(
            "yaml_error",
            f"YAML parse error at line {line}: {exc}",
        ) from exc

    if root is None:
        return None, []

    # Walk nodes with explicit stack for depth & count limits, detecting duplicate keys
    duplicate_key_findings: list[Finding] = []
    nodes_visited = 0
    # stack holds: (node, depth)
    stack: list[tuple[Node, int]] = [(root, 1)]

    while stack:
        curr_node, depth = stack.pop()
        nodes_visited += 1
        if nodes_visited > max_nodes:
            raise ComposeLintError(
                "too_many_nodes",
                f"Node count exceeded limit of {max_nodes}",
            )
        if depth > max_depth:
            raise ComposeLintError(
                "too_deep",
                f"YAML depth exceeded limit of {max_depth}",
            )

        if isinstance(curr_node, MappingNode):
            seen_keys: set[str] = set()
            for key_node, val_node in curr_node.value:
                if isinstance(key_node, ScalarNode):
                    key_str = str(key_node.value)
                    if key_str == "<<":
                        # YAML merge key
                        pass
                    elif key_str in seen_keys:
                        duplicate_key_findings.append(
                            Finding(
                                rule="CL008",
                                severity="error",
                                service=None,
                                line=_node_line(key_node),
                                message=f"duplicate mapping key '{key_str}'",
                            )
                        )
                    else:
                        seen_keys.add(key_str)
                stack.append((val_node, depth + 1))
                stack.append((key_node, depth + 1))
        elif isinstance(curr_node, SequenceNode):
            for item in curr_node.value:
                stack.append((item, depth + 1))

    return root, duplicate_key_findings


def _is_scalar(node: Node) -> bool:
    return isinstance(node, ScalarNode)


def _get_mapping_dict(node: Node) -> dict[str, tuple[Node, Node]]:
    """Return dict mapping key_name -> (key_node, val_node) for the first occurrences."""
    res: dict[str, tuple[Node, Node]] = {}
    if not isinstance(node, MappingNode):
        return res
    for kn, vn in node.value:
        if isinstance(kn, ScalarNode) and str(kn.value) not in res:
            res[str(kn.value)] = (kn, vn)
    return res


def _check_image(image_node: Node, service_name: str) -> Finding | None:
    if not isinstance(image_node, ScalarNode):
        return None
    image_str = str(image_node.value).strip()
    # An image with a digest: e.g. app@sha256:64chars
    if "@" in image_str:
        return None

    # Tag is after the last ':' only when no '/' follows it
    last_colon = image_str.rfind(":")
    last_slash = image_str.rfind("/")
    has_tag = last_colon > last_slash

    if not has_tag:
        return Finding(
            rule="CL003",
            severity="warning",
            service=service_name,
            line=_node_line(image_node),
            message=f"service '{service_name}' specifies image without explicit tag or digest",
        )
    tag = image_str[last_colon + 1 :]
    if tag == "latest":
        return Finding(
            rule="CL003",
            severity="warning",
            service=service_name,
            line=_node_line(image_node),
            message=f"service '{service_name}' uses ':latest' image tag",
        )
    return None


def _check_volume(val_node: Node, service_name: str) -> list[Finding]:
    findings: list[Finding] = []
    # Volumes can be scalar strings or mapping items
    if isinstance(val_node, ScalarNode):
        vol_str = str(val_node.value)
        # Short-form: [SOURCE:]TARGET[:MODE]
        # e.g. /var/run/docker.sock:/var/run/docker.sock or docker.sock
        parts = vol_str.split(":")
        source = parts[0]
        if source.endswith("docker.sock"):
            findings.append(
                Finding(
                    rule="CL002",
                    severity="error",
                    service=service_name,
                    line=_node_line(val_node),
                    message=f"service '{service_name}' mounts docker.sock",
                )
            )
    elif isinstance(val_node, MappingNode):
        mapping = _get_mapping_dict(val_node)
        if "source" in mapping:
            src_node = mapping["source"][1]
            if isinstance(src_node, ScalarNode) and str(src_node.value).endswith("docker.sock"):
                findings.append(
                    Finding(
                        rule="CL002",
                        severity="error",
                        service=service_name,
                        line=_node_line(src_node),
                        message=f"service '{service_name}' mounts docker.sock",
                    )
                )
    return findings


def _check_port(port_node: Node, service_name: str) -> Finding | None:
    if isinstance(port_node, ScalarNode):
        val = str(port_node.value).strip()
        # Short forms:
        # '80' -> bare container port (not flagged)
        # '8080:80' -> HOST:CONTAINER (flagged)
        # '8080-8085:80-85' -> flagged
        # '127.0.0.1:8080:80' -> IP:HOST:CONTAINER (not flagged)
        # '[::1]:8080:80' -> IPv6 host ip
        parts = val.split(":")
        if len(parts) == 1:
            # bare port
            return None
        if len(parts) == 2:
            # HOST:CONTAINER
            return Finding(
                rule="CL004",
                severity="warning",
                service=service_name,
                line=_node_line(port_node),
                message=f"service '{service_name}' publishes port without host IP binding",
            )
        if len(parts) >= 3:
            # Has an IP part; usually IP:HOST:CONTAINER
            return None
    elif isinstance(port_node, MappingNode):
        mapping = _get_mapping_dict(port_node)
        if "published" in mapping and "host_ip" not in mapping:
            return Finding(
                rule="CL004",
                severity="warning",
                service=service_name,
                line=_node_line(mapping["published"][0]),
                message=f"service '{service_name}' publishes port without host IP binding",
            )
    return None


def _check_env_item(key_str: str, val_str: str, node: Node, service_name: str) -> Finding | None:
    if SECRET_KEY_PATTERN.search(key_str) and val_str and "$" not in val_str:
        # Report line of offending node, naming the key only
        msg = f"service '{service_name}' sets sensitive environment key '{key_str}' in plaintext"
        return Finding(
            rule="CL005",
            severity="error",
            service=service_name,
            line=_node_line(node),
            message=msg,
        )
    return None


def _check_cap_add(item_node: Node, service_name: str) -> Finding | None:
    if isinstance(item_node, ScalarNode):
        val = str(item_node.value).strip().upper()
        if val in ("ALL", "SYS_ADMIN"):
            return Finding(
                rule="CL010",
                severity="error",
                service=service_name,
                line=_node_line(item_node),
                message=f"service '{service_name}' adds dangerous capability '{val}'",
            )
    return None


def lint(
    text: str,
    *,
    filename: str = "compose.yaml",
    disable: Sequence[str] = (),
    max_bytes: int = 1_048_576,
    max_nodes: int = 100_000,
    max_depth: int = 64,
) -> list[Finding]:
    """Lint Docker Compose YAML text and return detected findings."""
    for d in disable:
        if d not in KNOWN_RULES:
            raise ComposeLintError("invalid_option", f"Unknown rule in disable option: {d}")

    disabled_set = set(disable)

    root, duplicate_findings = _parse_yaml_tree(
        text=text,
        filename=filename,
        max_bytes=max_bytes,
        max_nodes=max_nodes,
        max_depth=max_depth,
    )

    findings: list[Finding] = []
    if "CL008" not in disabled_set:
        findings.extend(duplicate_findings)

    if root is None:
        return findings

    if not isinstance(root, MappingNode):
        raise ComposeLintError("invalid_compose", "Root must be a YAML mapping")

    top_mapping = _get_mapping_dict(root)

    # Rule CL009: top-level version key, obsolete in the Compose Specification
    if "version" in top_mapping and "CL009" not in disabled_set:
        ver_key_node, _ = top_mapping["version"]
        findings.append(
            Finding(
                rule="CL009",
                severity="warning",
                service=None,
                line=_node_line(ver_key_node),
                message="top-level 'version' key is obsolete in the Compose Specification",
            )
        )

    services_pair = top_mapping.get("services")
    if not services_pair:
        # Compose requires services or top-level elements, if empty or missing
        return [f for f in findings if f.rule not in disabled_set]

    services_node = services_pair[1]
    if not isinstance(services_node, MappingNode):
        raise ComposeLintError(
            "invalid_compose",
            "'services' must be a mapping",
        )

    services_dict = _get_mapping_dict(services_node)
    all_service_names = set(services_dict.keys())

    for service_name, (_, svc_node) in services_dict.items():
        if not isinstance(svc_node, MappingNode):
            continue

        svc_map = _get_mapping_dict(svc_node)

        # CL001: privileged: true
        if "privileged" in svc_map and "CL001" not in disabled_set:
            _, priv_val_node = svc_map["privileged"]
            if isinstance(priv_val_node, ScalarNode) and str(priv_val_node.value).lower() == "true":
                findings.append(
                    Finding(
                        rule="CL001",
                        severity="error",
                        service=service_name,
                        line=_node_line(priv_val_node),
                        message=f"service '{service_name}' runs in privileged mode",
                    )
                )

        # CL002: docker.sock mounted
        if "volumes" in svc_map and "CL002" not in disabled_set:
            _, vols_node = svc_map["volumes"]
            if isinstance(vols_node, SequenceNode):
                for v_item in vols_node.value:
                    findings.extend(_check_volume(v_item, service_name))

        # CL003: image without tag or latest
        if "image" in svc_map and "CL003" not in disabled_set:
            _, img_val = svc_map["image"]
            img_finding = _check_image(img_val, service_name)
            if img_finding:
                findings.append(img_finding)

        # CL004: published port without host IP
        if "ports" in svc_map and "CL004" not in disabled_set:
            _, ports_val = svc_map["ports"]
            if isinstance(ports_val, SequenceNode):
                for p_item in ports_val.value:
                    p_finding = _check_port(p_item, service_name)
                    if p_finding:
                        findings.append(p_finding)

        # CL005: plaintext secret in environment
        if "environment" in svc_map and "CL005" not in disabled_set:
            _, env_val = svc_map["environment"]
            if isinstance(env_val, MappingNode):
                for ek, ev in env_val.value:
                    if isinstance(ek, ScalarNode) and isinstance(ev, ScalarNode):
                        f = _check_env_item(str(ek.value), str(ev.value), ev, service_name)
                        if f:
                            findings.append(f)
            elif isinstance(env_val, SequenceNode):
                for env_item in env_val.value:
                    if isinstance(env_item, ScalarNode):
                        item_val = str(env_item.value)
                        if "=" in item_val:
                            ek_str, ev_str = item_val.split("=", 1)
                            f = _check_env_item(ek_str.strip(), ev_str, env_item, service_name)
                            if f:
                                findings.append(f)

        # CL006: network_mode: host
        if "network_mode" in svc_map and "CL006" not in disabled_set:
            _, net_val = svc_map["network_mode"]
            if isinstance(net_val, ScalarNode) and str(net_val.value).strip().lower() == "host":
                findings.append(
                    Finding(
                        rule="CL006",
                        severity="warning",
                        service=service_name,
                        line=_node_line(net_val),
                        message=f"service '{service_name}' uses host network mode",
                    )
                )

        # CL007: depends_on naming undefined service
        if "depends_on" in svc_map and "CL007" not in disabled_set:
            _, dep_val = svc_map["depends_on"]
            if isinstance(dep_val, SequenceNode):
                for item in dep_val.value:
                    if isinstance(item, ScalarNode):
                        dep_name = str(item.value).strip()
                        if dep_name not in all_service_names:
                            msg = (
                                f"service '{service_name}' depends on "
                                f"undefined service '{dep_name}'"
                            )
                            findings.append(
                                Finding(
                                    rule="CL007",
                                    severity="error",
                                    service=service_name,
                                    line=_node_line(item),
                                    message=msg,
                                )
                            )
            elif isinstance(dep_val, MappingNode):
                for dep_key, _ in dep_val.value:
                    if isinstance(dep_key, ScalarNode):
                        dep_name = str(dep_key.value).strip()
                        if dep_name not in all_service_names:
                            msg = (
                                f"service '{service_name}' depends on "
                                f"undefined service '{dep_name}'"
                            )
                            findings.append(
                                Finding(
                                    rule="CL007",
                                    severity="error",
                                    service=service_name,
                                    line=_node_line(dep_key),
                                    message=msg,
                                )
                            )

        # CL010: cap_add containing ALL or SYS_ADMIN
        if "cap_add" in svc_map and "CL010" not in disabled_set:
            _, cap_val = svc_map["cap_add"]
            if isinstance(cap_val, SequenceNode):
                for item in cap_val.value:
                    cap_finding = _check_cap_add(item, service_name)
                    if cap_finding:
                        findings.append(cap_finding)

    # Sort findings by line, then rule
    findings.sort(key=lambda f: (f.line, f.rule))
    return findings


def format_findings(
    findings: Sequence[Finding],
    fmt: Literal["text", "json"],
    *,
    filename: str = "compose.yaml",
) -> str:
    """Format findings into a text or JSON report string."""
    if fmt == "json":
        data = [
            {
                "filename": filename,
                "rule": f.rule,
                "severity": f.severity,
                "service": f.service,
                "line": f.line,
                "message": f.message,
            }
            for f in findings
        ]
        return json.dumps(data, indent=2)
    if fmt == "text":
        lines = [f"{filename}:{f.line} {f.rule} {f.severity} {f.message}" for f in findings]
        return "\n".join(lines)
    raise ValueError(f"Unsupported format: {fmt}")
