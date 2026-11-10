#!/usr/bin/env sh
#
# Copies Go porte's conformance vectors into tests/vectors/.
#
#   sh scripts/sync-vectors.sh ~/Code/Facile/porte-wt-vectors   a local checkout, at its HEAD
#   sh scripts/sync-vectors.sh ~/Code/Facile/porte v0.16.1       a local checkout, at a tag
#
# It copies conformance/vectors/*.json and conformance/testdata/*, then writes
# tests/vectors/SOURCE from the commit it read. Review the diff, then run the tests.

set -eu

repo="${1:?usage: sync-vectors.sh <porte checkout> [tag]}"
ref="${2:-HEAD}"
root="$(git rev-parse --show-toplevel)"
out="$root/tests/vectors"
commit="$(git -C "$repo" rev-parse "$ref^{commit}")"
tag="$(git -C "$repo" describe --tags --exact-match "$commit" 2>/dev/null || echo "$commit")"

mkdir -p "$out/testdata"
for path in $(git -C "$repo" ls-tree --name-only "$commit" conformance/vectors/ conformance/testdata/); do
  case "$path" in
    conformance/vectors/*.json) git -C "$repo" show "$commit:$path" > "$out/$(basename "$path")" ;;
    conformance/testdata/*) git -C "$repo" show "$commit:$path" > "$out/testdata/$(basename "$path")" ;;
  esac
done
printf 'github.com/FacileStudio/porte@%s\n%s\n' "$tag" "$commit" > "$out/SOURCE"
echo "sync-vectors: copied the vectors of $tag ($commit) into tests/vectors"
