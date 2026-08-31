#!/usr/bin/env bash
set -euo pipefail

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
path="$root/internal/iamlivecatalog/upstream"
relative_path="internal/iamlivecatalog/upstream"
url="${IAMLIVE_SUBMODULE_URL:-https://github.com/iann0036/iamlive.git}"
commit="3ec1a40e560c2f00ec82c50223add810e2567efb"
patterns=(/LICENSE /NOTICE /iamlivecore/map.json /iamlivecore/iam_definition.json '/iamlivecore/apis/**')
mode=init
case "${1:-}" in
  "") ;;
  --check) mode=check ;;
  *) echo "usage: $0 [--check]" >&2; exit 2 ;;
esac

canonical_dir() {
  (CDPATH= cd -- "$1" && pwd -P)
}

# A parent repository can answer git -C for an empty child directory.  Require
# both the nested-repository marker and an exact top-level identity before
# accepting that answer.
is_nested_repo() {
  [[ -d "$1" && ( -f "$1/.git" || -d "$1/.git" ) ]] || return 1
  local expected actual
  expected=$(canonical_dir "$1") || return 1
  actual=$(git -C "$1" rev-parse --show-toplevel 2>/dev/null) || return 1
  actual=$(canonical_dir "$actual") || return 1
  [[ "$actual" == "$expected" ]]
}

has_gitlink() {
  git -C "$root" ls-files --stage -- "$relative_path" | awk '$1 == "160000" { found=1 } END { exit !found }'
}

if [[ "$mode" == init ]] && ! is_nested_repo "$path"; then
  if has_gitlink; then
    # This also initializes an empty staged gitlink directory, rather than
    # allowing git -C to walk up into the superproject.
    git -C "$root" submodule update --init -- "$relative_path"
  else
    # A source tree may contain an empty placeholder, but never remove an
    # ordinary or symlinked directory which could hide user data.
    if [[ -e "$path" ]]; then
      [[ -d "$path" && ! -L "$path" && -z "$(find "$path" -mindepth 1 -maxdepth 1 -print -quit)" ]] || {
        echo "upstream path is not a real nested repository and has no gitlink" >&2
        exit 1
      }
      rmdir "$path"
    fi
    mkdir -p "$(dirname "$path")"
    git -c http.version=HTTP/1.1 clone --no-checkout "$url" "$path"
  fi
fi

# Check mode intentionally reaches no mutating command, including mkdir,
# initialization, config, checkout, read-tree, or clone.
if ! is_nested_repo "$path"; then
  echo "iamlive submodule is not an initialized nested repository: $path" >&2
  exit 1
fi
sparse_file=$(git -C "$path" rev-parse --git-path info/sparse-checkout)
case "$sparse_file" in
  /*) ;;
  *) sparse_file="$path/$sparse_file" ;;
esac

if [[ "$mode" == init ]]; then
  mkdir -p "$(dirname "$sparse_file")"
  printf '%s\n' "${patterns[@]}" > "$sparse_file"
  git -C "$path" config core.sparseCheckout true
  git -C "$path" config core.sparseCheckoutCone false
  git -C "$path" checkout --detach "$commit"
  git -C "$path" read-tree -mu HEAD
fi

actual=$(git -C "$path" rev-parse HEAD)
[[ "$actual" == "$commit" ]] || { echo "unexpected iamlive revision: $actual" >&2; exit 1; }
[[ "$(git -C "$path" config --local --bool core.sparseCheckout)" == true ]] || {
  echo "iamlive sparse checkout is disabled" >&2; exit 1;
}
[[ "$(git -C "$path" config --local --bool core.sparseCheckoutCone)" == false ]] || {
  echo "iamlive sparse checkout must use non-cone patterns" >&2; exit 1;
}
[[ -f "$sparse_file" ]] || { echo "missing sparse-checkout file" >&2; exit 1; }
if ! cmp -s "$sparse_file" <(printf '%s\n' "${patterns[@]}"); then
  echo "iamlive sparse checkout patterns are not minimal" >&2; exit 1
fi

while IFS= read -r f; do
  rel=${f#"$path/"}
  case "$rel" in
    LICENSE|NOTICE|iamlivecore/map.json|iamlivecore/iam_definition.json) ;;
    iamlivecore/apis/*/*/api-2.json) ;;
    *) echo "unexpected selected iamlive file: $rel" >&2; exit 1 ;;
  esac
done < <(find "$path" -path "$path/.git" -prune -o -type f -print)
for f in LICENSE NOTICE iamlivecore/map.json iamlivecore/iam_definition.json; do
  [[ -s "$path/$f" ]] || { echo "missing selected iamlive file: $f" >&2; exit 1; }
done
[[ -n "$(find "$path/iamlivecore/apis" -type f -name api-2.json -print -quit 2>/dev/null)" ]] || {
  echo "missing selected iamlive API models" >&2; exit 1;
}
if find "$path" -path "$path/.git" -prune -o \( -name go.mod -o -name go.sum \) -print | grep -q .; then
  echo "nested Go module is present in sparse iamlive checkout" >&2; exit 1
fi
printf 'iamlive submodule: PASS %s\n' "$actual"
