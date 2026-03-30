#!/bin/bash

# Builds and publishes multi-arch Docker images for hypersnap.
# Replaces the GitHub Actions publish workflow — runnable from any machine with Docker.
#
# Prerequisites:
#   docker login   (must be authenticated to push to Docker Hub)
#   docker buildx  (for multi-arch builds; included with Docker Desktop)
#
# Usage:
#   ./scripts/deploy.sh                # Build + push both arches, create manifest, tag latest
#   ./scripts/deploy.sh --no-latest    # Build + push but don't update :latest tag
#   ./scripts/deploy.sh --arch amd64   # Build + push only one architecture (no manifest)
#   ./scripts/deploy.sh --dry-run      # Build locally without pushing (verify only)
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
    *)
      echo "Unknown option: $1"
      echo "Usage: $0 [--no-latest] [--arch amd64|arm64] [--dry-run]"
      exit 1
      ;;
  esac
done

if [ "$DRY_RUN" = true ]; then
  echo "==> DRY RUN: building $IMAGE version $SNAPCHAIN_VERSION (no push)"
else
  echo "==> Deploying $IMAGE version $SNAPCHAIN_VERSION"
fi

# Ensure buildx builder exists
BUILDER_NAME="hypersnap-builder"
if ! docker buildx inspect "$BUILDER_NAME" &>/dev/null; then
  echo "==> Creating buildx builder: $BUILDER_NAME"
  docker buildx create --name "$BUILDER_NAME" --use --driver docker-container
else
  docker buildx use "$BUILDER_NAME"
fi

build_and_push() {
  local arch="$1"
  local tag="${IMAGE}:${SNAPCHAIN_VERSION}-${arch}"
  echo "==> Building $tag"
  if [ "$DRY_RUN" = true ]; then
    docker buildx build \
      --platform "linux/${arch}" \
      --tag "$tag" \
      --load \
      -f Dockerfile \
      .
    echo "==> Built $tag (local only, not pushed)"
    echo "==> Verify with: docker run --rm $tag --help"
    echo "==> Or run interactively: docker run --rm -it $tag /bin/bash"
  else
    docker buildx build \
      --platform "linux/${arch}" \
      --tag "$tag" \
      --push \
      -f Dockerfile \
      .
    echo "==> Pushed $tag"
  fi
}

create_manifest() {
  local tag="$1"
  if [ "$DRY_RUN" = true ]; then
    echo "==> [skip] Would create multi-arch manifest: ${IMAGE}:${tag}"
    return
  fi
  echo "==> Creating multi-arch manifest: ${IMAGE}:${tag}"
  # Remove existing manifest if present (docker manifest has no --force on create)
  docker manifest rm "${IMAGE}:${tag}" 2>/dev/null || true
  docker manifest create "${IMAGE}:${tag}" \
    "${IMAGE}:${SNAPCHAIN_VERSION}-amd64" \
    "${IMAGE}:${SNAPCHAIN_VERSION}-arm64"
  docker manifest push "${IMAGE}:${tag}"
  echo "==> Pushed manifest ${IMAGE}:${tag}"
}

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

if [ -n "$SINGLE_ARCH" ]; then
  # Single-arch mode
  build_and_push "$SINGLE_ARCH"
  if [ "$DRY_RUN" = true ]; then
    echo "==> Dry run complete. Image available locally."
  else
    echo "==> Done (single arch: $SINGLE_ARCH)"
  fi
else
  # Full multi-arch deploy
  build_and_push "amd64"
  build_and_push "arm64"

  # Create versioned manifest
  create_manifest "$SNAPCHAIN_VERSION"

  # Optionally tag as latest
  if [ "$TAG_LATEST" = true ]; then
    create_manifest "latest"
  fi

  echo "==> Deploy complete: $IMAGE:$SNAPCHAIN_VERSION"
fi
