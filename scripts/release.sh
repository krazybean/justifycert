#!/usr/bin/env bash
set -e

OLD_VERSION=$(grep '^version =' pyproject.toml | sed -E 's/version = "(.*)"/\1/')

if [[ ! $OLD_VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Error: could not parse version from pyproject.toml"
  exit 1
fi

IFS='.' read -r MAJOR MINOR PATCH <<< "$OLD_VERSION"

echo "Select version bump:"
echo "1) patch"
echo "2) minor"
echo "3) major"
echo "4) manual"
read -p "Choice [1-4]: " choice

case "$choice" in
  1|"")
    PATCH=$((PATCH + 1))
    ;;
  2)
    MINOR=$((MINOR + 1))
    PATCH=0
    ;;
  3)
    MAJOR=$((MAJOR + 1))
    MINOR=0
    PATCH=0
    ;;
  4)
    read -p "Enter new version (x.y.z): " NEW_VERSION
    ;;
  *)
    echo "Invalid choice"
    exit 1
    ;;
esac

if [ "${choice}" != "4" ]; then
  NEW_VERSION="${MAJOR}.${MINOR}.${PATCH}"
fi

if [[ ! $NEW_VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Error: invalid new version: $NEW_VERSION"
  exit 1
fi

echo "Bumping version: $OLD_VERSION -> $NEW_VERSION"
sed -i '' "s/version = \"$OLD_VERSION\"/version = \"$NEW_VERSION\"/" pyproject.toml
sed -i '' "s/__version__ = \"$OLD_VERSION\"/__version__ = \"$NEW_VERSION\"/" justifycert/__init__.py

echo "Cleaning build artifacts..."
rm -rf dist/ build/ *.egg-info

echo "Building package..."
python3 -m build

if [ -z "$(ls -A dist/)" ]; then
  echo "Build failed — no artifacts"
  exit 1
fi

read -p "Upload to PyPI version $NEW_VERSION? (y/N): " confirm
if [ "$confirm" != "y" ]; then
  echo "Upload cancelled"
  exit 0
fi

echo "Uploading..."
twine upload --config-file ~/.pypirc dist/*
