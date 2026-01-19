"""
Ensure docker-compose.yml passes all of the config advertised in .env.example. Otherwise, the user may configure
something in .env that isn't applied.
"""

import re
from pathlib import Path


def parse_env_example_keys(path: Path) -> set[str]:
    """
    Extract env var keys from .env.example.

    Rules:
      - Ignore blank lines.
      - Ignore full-line comments *unless* the comment contains a KEY=VALUE example.
      - Consider both:
          LANGFUSE_HOST=http://...
          # LANGFUSE_HOST=http://...
    """
    keys: set[str] = set()

    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            continue

        # Allow commented examples: "# KEY=VALUE"
        if line.startswith("#"):
            line = line[1:].lstrip()
            if not line or line.startswith("#"):
                continue

        if line.startswith("export "):
            line = line[len("export "):].lstrip()

        if "=" not in line:
            continue

        key = line.split("=", 1)[0].strip()
        if key:
            keys.add(key)

    return keys


# Matches ${VAR}, ${VAR:-default}, ${VAR-default}, ${VAR:?err}, etc. (basic).
_VAR_USE_RE = re.compile(r"\$\{\s*([A-Za-z_][A-Za-z0-9_]*)\b[^}]*\}")


def parse_compose_used_vars(path: Path) -> set[str]:
    """
    Extract env var *uses* from docker-compose.yml by scanning for ${VAR...} patterns.

    This intentionally does NOT require the YAML env key to match the referenced VAR,
    and works for both forms:
      - list form:  - KEY=${VAR:-default}
      - dict form:  KEY: ${VAR:-default}
    """
    text = path.read_text(encoding="utf-8")
    return set(_VAR_USE_RE.findall(text))


def missing_used_vars(env_example: Path, docker_compose: Path) -> list[str]:
    required = parse_env_example_keys(env_example)
    used = parse_compose_used_vars(docker_compose)
    return sorted(required - used)


def test_all_env_example_vars_are_used_somewhere_in_compose(tmp_path: Path) -> None:
    env_example = tmp_path / ".env.example"
    compose = tmp_path / "docker-compose.yml"

    env_example.write_text(
        "\n".join(
            [
                "# LANGFUSE_HOST=http://your-custom-langfuse:3000",
                "LANGFUSE_PUBLIC_KEY=cyber-public",
                "LANGFUSE_ENCRYPTION_KEY=secret",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    compose.write_text(
        "\n".join(
            [
                "services:",
                "  app:",
                "    environment:",
                "      - PUBLIC=${LANGFUSE_PUBLIC_KEY}",
                "      - LANGFUSE_HOST=${LANGFUSE_HOST:-http://langfuse-web:3000}",
                "      ENCRYPTION_KEY: ${LANGFUSE_ENCRYPTION_KEY:-}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    assert missing_used_vars(env_example, compose) == []


def test_missing_var_is_reported(tmp_path: Path) -> None:
    env_example = tmp_path / ".env.example"
    compose = tmp_path / "docker-compose.yml"

    env_example.write_text(
        "\n".join(
            [
                "LANGFUSE_HOST=http://x",
                "LANGFUSE_PUBLIC_KEY=cyber-public",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    compose.write_text(
        "\n".join(
            [
                "services:",
                "  app:",
                "    environment:",
                "      - SOME_KEY=${LANGFUSE_PUBLIC_KEY}",
                "      # LANGFUSE_HOST not referenced",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    assert missing_used_vars(env_example, compose) == ["LANGFUSE_HOST"]


def test_dict_form_is_accepted(tmp_path: Path) -> None:
    env_example = tmp_path / ".env.example"
    compose = tmp_path / "docker-compose.yml"

    env_example.write_text("LANGFUSE_ENCRYPTION_KEY=secret\n", encoding="utf-8")
    compose.write_text(
        "\n".join(
            [
                "services:",
                "  app:",
                "    environment:",
                "      ENCRYPTION_KEY: ${LANGFUSE_ENCRYPTION_KEY:-}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    assert missing_used_vars(env_example, compose) == []


def test_all_env_example_keys_are_passed_through():
    root = Path(__file__).parent.parent
    assert missing_used_vars(root / ".env.example", root / "docker" / "docker-compose.yml") == []
