#!/usr/bin/env sh
#
# Copies Go porte's conformance vectors into tests/vectors and records the tag they came from.
#
#   sh scripts/sync-vectors.sh v0.20.0                        clone FacileStudio/porte at a tag
#   sh scripts/sync-vectors.sh ~/Code/Facile/porte v0.20.0    read a local checkout at that tag
#
# It copies conformance/vectors/*.json and conformance/testdata/*, and writes the tag to
# tests/vectors/SOURCE. Each file keeps its own "source": Go stamps a subject with the release
# of its module (porte, porte/mcpauth, porte/directory). The JSON files are replaced as a set,
# so a vector Go adds or drops shows up as a new or deleted file. CI re-runs this against the
# recorded tag and fails on any difference, new files included:
#
#   sh scripts/sync-vectors.sh "$(cat tests/vectors/SOURCE)"
#   git add --intent-to-add tests/vectors && git diff --exit-code tests/vectors

set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  echo "usage: $0 <tag> | $0 <porte checkout> <tag>" >&2
  exit 2
fi

root="$(git rev-parse --show-toplevel)"
target="$root/tests/vectors"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

if [ "$#" -eq 2 ]; then
  repo="$1"
  tag="$2"
else
  tag="$1"
  repo="$scratch/porte"
  git -c advice.detachedHead=false clone --quiet --depth 1 --branch "$tag" https://github.com/FacileStudio/porte "$repo"
fi

commit="$(git -C "$repo" rev-parse "$tag^{commit}")"
mkdir -p "$scratch/out/testdata"
for path in $(git -C "$repo" ls-tree --name-only "$commit" conformance/vectors/ conformance/testdata/); do
  case "$path" in
    conformance/vectors/*.json) git -C "$repo" show "$commit:$path" > "$scratch/out/$(basename "$path")" ;;
    conformance/testdata/*) git -C "$repo" show "$commit:$path" > "$scratch/out/testdata/$(basename "$path")" ;;
  esac
done

set -- "$scratch"/out/*.json
if [ ! -f "$1" ]; then
  echo "sync-vectors: no vector file in porte $tag" >&2
  exit 1
fi

mkdir -p "$target/testdata"
rm -f "$target"/*.json "$target"/testdata/*
cp "$@" "$target/"
cp "$scratch"/out/testdata/* "$target/testdata/"
echo "$tag" > "$target/SOURCE"
echo "sync-vectors: $# files from porte $tag ($commit)"
