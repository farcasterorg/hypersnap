#!/bin/bash

# Builds and publishes multi-arch Docker images for hypersnap.
# Replaces the GitHub Actions publish workflow — runnable from any machine with Docker.
#
# Prerequisites:
#   docker login   (must be authenticated to push to Docker Hub)
#   docker buildx  (for multi-arch builds; included with Docker Desktop)
#
# Usage:
#   ./scripts/deploy.sh                    # Build + push both arches, tag version + latest
#   ./scripts/deploy.sh --no-latest        # Build + push but don't update :latest tag
#   ./scripts/deploy.sh --arch amd64       # Build + push only one architecture
#   ./scripts/deploy.sh --dry-run          # Build locally without pushing (verify only)
#   ./scripts/deploy.sh --channel nightly  # Publish as nightly-{version}-{commit} / nightly-latest
#
# MUST be run from the root of the repository.

set -euo pipefail

IMAGE="farcasterorg/hypersnap"
SNAPCHAIN_VERSION=$(awk -F '"' '/^version =/ {print $2}' Cargo.toml)

if [ -z "$SNAPCHAIN_VERSION" ]; then
  echo "Error: could not read version from Cargo.toml"
  exit 1
fi

TAG_LATEST=true
SINGLE_ARCH=""
DRY_RUN=false
CHANNEL=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-latest)
      TAG_LATEST=false
      shift
      ;;
    --arch)
      SINGLE_ARCH="$2"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=true
      shift
      ;;
    --channel)
      CHANNEL="$2"
      shift 2
      ;;
    *)
      echo "Unknown option: $1"
      echo "Usage: $0 [--no-latest] [--arch amd64|arm64] [--dry-run] [--channel NAME]"
      exit 1
      ;;
  esac
done

# When a channel is set, prefix all version tags with it and append the short git commit.
# e.g. --channel nightly → nightly-0.11.6-dc8d8df, nightly-latest
if [ -n "$CHANNEL" ]; then
  GIT_SHORT=$(git rev-parse --short HEAD)
  VERSION_TAG="${CHANNEL}-${SNAPCHAIN_VERSION}-${GIT_SHORT}"
  LATEST_TAG="${CHANNEL}-latest"
else
  VERSION_TAG="${SNAPCHAIN_VERSION}"
  LATEST_TAG="latest"
fi

if [ "$DRY_RUN" = true ]; then
  echo "==> DRY RUN: building $IMAGE version $VERSION_TAG (no push)"
else
  echo "==> Deploying $IMAGE version $VERSION_TAG"
fi

# Ensure buildx builder exists
BUILDER_NAME="hypersnap-builder"
if ! docker buildx inspect "$BUILDER_NAME" &>/dev/null; then
  echo "==> Creating buildx builder: $BUILDER_NAME"
  docker buildx create --name "$BUILDER_NAME" --use --driver docker-container
else
  docker buildx use "$BUILDER_NAME"
fi

# Default to host arch in dry-run mode if no arch specified
if [ "$DRY_RUN" = true ] && [ -z "$SINGLE_ARCH" ]; then
  HOST_ARCH=$(uname -m)
  case "$HOST_ARCH" in
    x86_64)  SINGLE_ARCH="amd64" ;;
    aarch64|arm64) SINGLE_ARCH="arm64" ;;
    *) echo "Error: unknown host architecture $HOST_ARCH"; exit 1 ;;
  esac
  echo "==> Dry run: defaulting to host architecture ($SINGLE_ARCH)"
fi

# Determine platforms
if [ -n "$SINGLE_ARCH" ]; then
  PLATFORMS="linux/${SINGLE_ARCH}"
else
  PLATFORMS="linux/amd64,linux/arm64"
fi

# Collect tags
TAGS="--tag ${IMAGE}:${VERSION_TAG}"
if [ "$TAG_LATEST" = true ] && [ -z "$SINGLE_ARCH" ]; then
  TAGS="$TAGS --tag ${IMAGE}:${LATEST_TAG}"
fi

# Build (and optionally push) with buildx.
# buildx --platform with multiple arches produces a proper multi-arch
# manifest in a single step, avoiding the "manifest list from manifest
# list" error that happens when composing separately-pushed arch tags.
echo "==> Building ${IMAGE}:${VERSION_TAG} for ${PLATFORMS}"
if [ "$DRY_RUN" = true ]; then
  docker buildx build \
    --platform "$PLATFORMS" \
    $TAGS \
    --load \
    -f Dockerfile \
    .
  echo "==> Built locally (not pushed)"
  echo "==> Verify with: docker run --rm ${IMAGE}:${VERSION_TAG} --help"
else
  docker buildx build \
    --platform "$PLATFORMS" \
    $TAGS \
    --push \
    -f Dockerfile \
    .
  echo "==> Pushed ${IMAGE}:${VERSION_TAG}"
  if [ "$TAG_LATEST" = true ] && [ -z "$SINGLE_ARCH" ]; then
    echo "==> Pushed ${IMAGE}:${LATEST_TAG}"
  fi
fi

echo "==> Deploy complete: $IMAGE:$VERSION_TAG"
