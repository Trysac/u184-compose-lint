"""Comprehensive tests for compose_lint covering all acceptance criteria and rules."""

from __future__ import annotations

import os
import tempfile

import pytest

from compose_lint import ComposeLintError, format_findings, lint
from compose_lint.__main__ import main


def test_acceptance_1_privileged_and_images() -> None:
    # lint('services:\n  db:\n    image: postgres\n    privileged: true\n') returns findings
    # whose (rule, line) pairs are [('CL003', 3), ('CL001', 4)], and image 'postgres:16' gives no CL003
    content = "services:\n  db:\n    image: postgres\n    privileged: true\n"
    findings = lint(content)
    pairs = [(f.rule, f.line) for f in findings]
    assert pairs == [("CL003", 3), ("CL001", 4)]

    content_fixed = "services:\n  db:\n    image: postgres:16\n    privileged: true\n"
    findings_fixed = lint(content_fixed)
    cl003 = [f for f in findings_fixed if f.rule == "CL003"]
    assert len(cl003) == 0


def test_acceptance_2_image_variations() -> None:
    # Images 'nginx', 'nginx:latest' and 'registry:5000/app' give CL003, while
    # 'registry:5000/app:1.2' and 'app@sha256:' followed by 64 'a' characters give none;
    # a service with build and no image gives none
    for img in ["nginx", "nginx:latest", "registry:5000/app"]:
        yaml_text = f"services:\n  web:\n    image: {img}\n"
        findings = lint(yaml_text)
        rules = [f.rule for f in findings]
        assert "CL003" in rules, f"Expected CL003 for image {img}"

    sha_img = "app@sha256:" + ("a" * 64)
    for img in ["registry:5000/app:1.2", sha_img]:
        yaml_text = f"services:\n  web:\n    image: {img}\n"
        findings = lint(yaml_text)
        rules = [f.rule for f in findings]
        assert "CL003" not in rules, f"Did not expect CL003 for image {img}"

    build_only = "services:\n  web:\n    build: .\n"
    findings = lint(build_only)
    assert len(findings) == 0


def test_acceptance_3_ports() -> None:
    # ports ['5432:5432'] and the long form {'target': 80, 'published': 8080} give CL004;
    # ['127.0.0.1:5432:5432'], ['80'] and {'target': 80, 'published': 8080, 'host_ip': '127.0.0.1'} give none
    content_short = """
services:
  db:
    image: postgres:16
    ports:
      - '5432:5432'
"""
    f_short = lint(content_short)
    assert any(f.rule == "CL004" for f in f_short)

    content_long = """
services:
  web:
    image: nginx:1.25
    ports:
      - target: 80
        published: 8080
"""
    f_long = lint(content_long)
    assert any(f.rule == "CL004" for f in f_long)

    content_ok_short = """
services:
  db:
    image: postgres:16
    ports:
      - '127.0.0.1:5432:5432'
      - '80'
"""
    f_ok_short = lint(content_ok_short)
    assert not any(f.rule == "CL004" for f in f_ok_short)

    content_ok_long = """
services:
  web:
    image: nginx:1.25
    ports:
      - target: 80
        published: 8080
        host_ip: '127.0.0.1'
"""
    f_ok_long = lint(content_ok_long)
    assert not any(f.rule == "CL004" for f in f_ok_long)


def test_acceptance_4_environment_secrets() -> None:
    # environment {'DB_PASSWORD': 'plain-sentinel'} gives CL005 whose message names 'DB_PASSWORD',
    # and the string 'plain-sentinel' appears in neither format_findings(f, 'text') nor format_findings(f, 'json');
    # ['API_TOKEN=${TOKEN}'] and {'DB_PASSWORD': ''} give none
    content = """
services:
  db:
    image: postgres:16
    environment:
      DB_PASSWORD: 'plain-sentinel'
"""
    findings = lint(content)
    cl005 = [f for f in findings if f.rule == "CL005"]
    assert len(cl005) == 1
    assert "DB_PASSWORD" in cl005[0].message
    assert "plain-sentinel" not in cl005[0].message

    text_out = format_findings(findings, "text")
    assert "plain-sentinel" not in text_out
    assert "DB_PASSWORD" in text_out

    json_out = format_findings(findings, "json")
    assert "plain-sentinel" not in json_out
    assert "DB_PASSWORD" in json_out

    content_ok = """
services:
  db:
    image: postgres:16
    environment:
      - 'API_TOKEN=${TOKEN}'
  app:
    image: myapp:1.0
    environment:
      DB_PASSWORD: ''
"""
    findings_ok = lint(content_ok)
    assert not any(f.rule == "CL005" for f in findings_ok)


def test_acceptance_5_depends_on_and_docker_sock() -> None:
    # depends_on ['cache'] (and the mapping form {'cache': {'condition': 'service_started'}})
    # without a cache service gives CL007 with message "service 'web' depends on undefined service 'cache'";
    # a volume '/var/run/docker.sock:/var/run/docker.sock' gives CL002
    content_list = """
services:
  web:
    image: nginx:1.25
    depends_on:
      - cache
"""
    f_list = lint(content_list)
    cl007_list = [f for f in f_list if f.rule == "CL007"]
    assert len(cl007_list) == 1
    assert cl007_list[0].message == "service 'web' depends on undefined service 'cache'"

    content_map = """
services:
  web:
    image: nginx:1.25
    depends_on:
      cache:
        condition: service_started
"""
    f_map = lint(content_map)
    cl007_map = [f for f in f_map if f.rule == "CL007"]
    assert len(cl007_map) == 1
    assert cl007_map[0].message == "service 'web' depends on undefined service 'cache'"

    content_sock = """
services:
  web:
    image: nginx:1.25
    volumes:
      - '/var/run/docker.sock:/var/run/docker.sock'
"""
    f_sock = lint(content_sock)
    assert any(f.rule == "CL002" for f in f_sock)


def test_acceptance_6_duplicate_key_version_cap_add_network() -> None:
    # A service mapping with the key 'image' twice gives CL008 at the line of the second key;
    # a top-level 'version: "3.8"' gives CL009 with severity 'warning';
    # cap_add ['SYS_ADMIN'] gives CL010 and network_mode 'host' gives CL006
    content = """version: "3.8"\nservices:\n  app:\n    image: postgres:16\n    image: redis:7\n    cap_add:\n      - SYS_ADMIN\n    network_mode: host\n"""
    findings = lint(content)
    rules = {f.rule: f for f in findings}
    assert "CL008" in rules
    # The second 'image' key is at line 5
    assert rules["CL008"].line == 5

    assert "CL009" in rules
    assert rules["CL009"].severity == "warning"

    assert "CL010" in rules
    assert rules["CL010"].severity == "error"

    assert "CL006" in rules
    assert rules["CL006"].severity == "warning"


def test_acceptance_7_bounds_and_errors() -> None:
    # A 1_048_577-byte input raises ComposeLintError with code 'input_too_large' (1_048_576 accepted);
    # 'services: [' raises code 'yaml_error' with the line;
    # 'services: []' raises code 'invalid_compose';
    # a nine-level billion-laughs alias document raises code 'too_many_nodes'
    big_content = " " * 1_048_577
    with pytest.raises(ComposeLintError) as exc_info:
        lint(big_content)
    assert exc_info.value.code == "input_too_large"

    # 1_048_576 accepted (blank string returns no findings)
    valid_big = " " * 1_048_576
    assert lint(valid_big) == []

    with pytest.raises(ComposeLintError) as exc_info:
        lint("services: [")
    assert exc_info.value.code == "yaml_error"

    with pytest.raises(ComposeLintError) as exc_info:
        lint("services: []")
    assert exc_info.value.code == "invalid_compose"

    # Billion laughs alias tree
    laughs = """
services:
  a: &a ["lol","lol","lol"]
  b: &b [*a,*a,*a]
  c: &c [*b,*b,*b]
  d: &d [*c,*c,*c]
  e: &e [*d,*d,*d]
  f: &f [*e,*e,*e]
  g: &g [*f,*f,*f]
  h: &h [*g,*g,*g]
  i: &i [*h,*h,*h]
"""
    with pytest.raises(ComposeLintError) as exc_info:
        lint(laughs, max_nodes=500)
    assert exc_info.value.code == "too_many_nodes"


def test_acceptance_8_disable_and_cli() -> None:
    # lint(text, disable=('CL009',)) suppresses CL009 and disable=('CL999',) raises code 'invalid_option';
    # CLI main(['compose.yaml']) returns 1 when an error-severity finding exists, 0 for warnings only and 2 for ComposeLintError or IO
    content = 'version: "3.8"\nservices:\n  web:\n    image: nginx:1.25\n'
    f_suppressed = lint(content, disable=("CL009",))
    assert not any(f.rule == "CL009" for f in f_suppressed)

    with pytest.raises(ComposeLintError) as exc_info:
        lint(content, disable=("CL999",))
    assert exc_info.value.code == "invalid_option"

    with tempfile.TemporaryDirectory() as tmpdir:
        # File with error
        err_file = os.path.join(tmpdir, "error_compose.yaml")
        with open(err_file, "w", encoding="utf-8") as f:
            f.write("services:\n  app:\n    image: postgres:16\n    privileged: true\n")
        assert main([err_file]) == 1

        # File with warning only (version + unpinned image)
        warn_file = os.path.join(tmpdir, "warn_compose.yaml")
        with open(warn_file, "w", encoding="utf-8") as f:
            f.write('version: "3.8"\nservices:\n  app:\n    image: postgres:latest\n')
        assert main([warn_file]) == 0

        # File with invalid YAML (ComposeLintError)
        invalid_file = os.path.join(tmpdir, "invalid.yaml")
        with open(invalid_file, "w", encoding="utf-8") as f:
            f.write("services: [")
        assert main([invalid_file]) == 2

        # Non-existent file (IO error)
        assert main([os.path.join(tmpdir, "does_not_exist.yaml")]) == 2


def test_cap_add_all() -> None:
    content = """
services:
  app:
    image: postgres:16
    cap_add:
      - ALL
"""
    findings = lint(content)
    assert any(f.rule == "CL010" for f in findings)


def test_volume_long_form_sock() -> None:
    content = """
services:
  app:
    image: postgres:16
    volumes:
      - type: bind
        source: /var/run/docker.sock
        target: /var/run/docker.sock
"""
    findings = lint(content)
    assert any(f.rule == "CL002" for f in findings)


def test_env_list_plaintext_secret() -> None:
    content = """
services:
  app:
    image: postgres:16
    environment:
      - SECRET_KEY=my-super-secret
      - SAFE_VAR=hello
"""
    findings = lint(content)
    cl005 = [f for f in findings if f.rule == "CL005"]
    assert len(cl005) == 1
    assert "SECRET_KEY" in cl005[0].message
    assert "my-super-secret" not in cl005[0].message


def test_root_not_mapping() -> None:
    with pytest.raises(ComposeLintError) as exc_info:
        lint("- a\n- b\n")
    assert exc_info.value.code == "invalid_compose"


def test_depth_limit() -> None:
    content = "a:\n" + "  " * 1 + "b:\n" + "  " * 2 + "c:\n" + "  " * 3 + "d: 1\n"
    with pytest.raises(ComposeLintError) as exc_info:
        lint(content, max_depth=3)
    assert exc_info.value.code == "too_deep"


def test_format_invalid() -> None:
    with pytest.raises(ValueError, match="Unsupported format"):
        format_findings([], "xml")  # type: ignore[arg-type]
