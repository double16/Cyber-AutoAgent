#!/usr/bin/env python3
import argparse
import json
import pathlib
import re
import sys
import os

UNDERSCORE_VERSION_PATTERN = re.compile(r'^(__version__\s*=\s*)"[^"]*"', re.MULTILINE)
DOCKER_IMAGE_VERSION_PATTERN = re.compile(r'^(\s*image:\s+caa:)[0-9.]+$', re.MULTILINE)
DOCKERFILE_VERSION_PATTERN = re.compile(r'(\s+org.opencontainers.image.version\s*=\s*)"[^"]*"', re.MULTILINE)

root_path = pathlib.Path(os.path.dirname(os.path.realpath(__file__)), '..', '..')


def replace_underscore_version(version, rel_paths: list[str]):
    for rel_path in rel_paths:
        path = pathlib.Path(root_path, rel_path)
        text = path.read_text(encoding="utf-8")

        new_text, count = UNDERSCORE_VERSION_PATTERN.subn(
            rf'\1"{version}"', text, count=1
        )

        if count == 0:
            print(
                f'{rel_path}: could not find a line starting with __version__ = "...".',
                file=sys.stderr,
            )
            continue

        if new_text == text:
            print(f"{rel_path}: __version__ is already {version}")
            continue

        path.write_text(new_text, encoding="utf-8")
        print(f"{rel_path}: Updated {path} to __version__ = {version}")


def replace_docker_image_version(version, rel_paths: list[str]):
    for rel_path in rel_paths:
        path = pathlib.Path(root_path, rel_path)
        text = path.read_text(encoding="utf-8")

        new_text, count = DOCKER_IMAGE_VERSION_PATTERN.subn(
            lambda m: m.group(1) + version,
            text,
            count=1,
        )

        if count == 0:
            print(
                f'{rel_path}: could not find a line starting with image: caa:...',
                file=sys.stderr,
            )
            continue

        if new_text == text:
            print(f"{rel_path}: image is already caa:{version}")
            continue

        path.write_text(new_text, encoding="utf-8")
        print(f"{rel_path}: Updated image: caa:{version}")


def replace_dockerfile_version(version, paths: list[pathlib.Path]):
    for path in paths:
        text = path.read_text(encoding="utf-8")

        new_text, count = DOCKERFILE_VERSION_PATTERN.subn(
            rf'\1"{version}"', text, count=1
        )

        if count == 0:
            print(
                f'{path}: could not find LABEL org.opencontainers.image.version = "...".',
                file=sys.stderr,
            )
            continue

        if new_text == text:
            print(f"{path}: org.opencontainers.image.version is already {version}")
            continue

        path.write_text(new_text, encoding="utf-8")
        print(f"{path}: Updated to org.opencontainers.image.version = {version}")


def update_pyproject_version(path: pathlib.Path, version: str) -> bool:
    """
    Update the version in the [project] section of a TOML file.

    Returns True if a change was made, False if already set to that value.
    Raises RuntimeError if [project] or version key is not found.
    """
    if not path.is_file():
        raise RuntimeError(f"File not found: {path}")

    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)

    in_project = False
    changed = False

    for i, line in enumerate(lines):
        stripped = line.strip()

        # Enter [project] section
        if stripped == "[project]":
            in_project = True
            continue

        # Leaving [project] section when another section starts
        if in_project and stripped.startswith("[") and stripped.endswith("]"):
            break

        if in_project and stripped.startswith("version"):
            # Handle lines like: version = "0.1.5"
            prefix, sep, value = line.partition("=")
            if not sep:
                continue  # malformed line, skip

            current_value = value.strip()
            # Expect something like: "0.1.5"
            if current_value == f'"{version}"':
                return False  # already up to date

            # Preserve original spacing around '=' but replace the value
            lines[i] = f'{prefix}{sep} "{version}"\n'
            changed = True
            break

    if not in_project:
        raise RuntimeError("No [project] section found in file.")

    if not changed:
        return False

    path.write_text("".join(lines), encoding="utf-8")
    return True


def update_tsx_header_version(path: pathlib.Path, version: str) -> bool:
    """
    Update the version in the Header element of a TOML file.

    Returns True if a change was made, False if already set to that value.
    Raises RuntimeError if Header element or version attribute is not found.
    """
    if not path.is_file():
        raise RuntimeError(f"File not found: {path}")

    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)

    in_header = False
    changed = False

    for i, line in enumerate(lines):
        stripped = line.strip()

        # Enter <Header section
        if stripped.startswith("<Header") or stripped.startswith("export const Header:"):
            in_header = True
            continue

        # Leaving <Header section when another section starts
        if in_header and (stripped.endswith("/>") or stripped.endswith("})")):
            break

        if in_header and stripped.startswith("version"):
            # Handle lines like: version = "0.1.5"
            prefix, sep, value = line.partition("=")
            if not sep:
                continue  # malformed line, skip

            current_value = value.strip()
            # Expect something like: "0.1.5"
            if current_value == f'"{version}"':
                return False  # already up to date

            # Preserve original spacing around '=' but replace the value
            lines[i] = f'{prefix}{sep}"{version}"'
            if current_value.endswith(","):
                lines[i] += ","
            lines[i] += '\n'
            changed = True
            break

    if not in_header:
        return False

    if not changed:
        return False

    path.write_text("".join(lines), encoding="utf-8")
    return True


def update_package_json_version(package_file: pathlib.Path, version: str):
    with open("src/modules/interfaces/react/package.json") as package_file:
        package = json.load(package_file)
    package["version"] = version
    with open("src/modules/interfaces/react/package.json", "w") as package_file:
        json.dump(package, package_file, indent=2)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Update software version in all the files"
    )
    parser.add_argument("version", help="New version string, e.g. 0.1.6")
    args = parser.parse_args()

    replace_underscore_version(args.version, ["src/__init__.py", "src/modules/__init__.py"])

    replace_docker_image_version(args.version, ["docker/docker-compose.yml"])

    update_pyproject_version(pathlib.Path(root_path, "pyproject.toml"), args.version)

    for root, dirs, files in os.walk(root_path):
        for file in filter(lambda f: f.endswith(".tsx"), files):
            file_path = pathlib.Path(root, file)
            update_tsx_header_version(file_path, args.version)
        if root.endswith("/docker"):
            for file in filter(lambda f: f.startswith("Dockerfile"), files):
                file_path = pathlib.Path(root, file)
                replace_dockerfile_version(args.version, [file_path])

    update_package_json_version(pathlib.Path(root_path, "src/modules/interfaces/react/package.json"), args.version)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
