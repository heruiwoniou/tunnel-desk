#!/usr/bin/env bash
# Create a GitHub Release only after every required installer is on disk.
# gh reads GH_TOKEN from the environment. This script does not print it.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="${RELEASE_ROOT:-$(cd "${script_dir}/.." && pwd)}"

: "${RELEASE_TAG:?RELEASE_TAG is required}"
: "${RELEASE_ASSETS:?RELEASE_ASSETS is required}"
: "${GITHUB_SHA:?GITHUB_SHA is required}"

notes="${RELEASE_NOTES:-${repo_root}/release-notes.md}"

mapfile -t asset_files < <(
  node "${script_dir}/version.mjs" stage-assets \
    --root "${repo_root}" \
    --assets "${RELEASE_ASSETS}" \
    --notes "${notes}" \
    --tag "${RELEASE_TAG}"
)

if [[ "${#asset_files[@]}" -eq 0 ]]; then
  echo "stage-assets produced no files" >&2
  exit 1
fi

for asset in "${asset_files[@]}"; do
  if [[ ! -s "${asset}" ]]; then
    echo "missing staged asset: ${asset}" >&2
    exit 1
  fi
done

if existing="$(gh release view "${RELEASE_TAG}" --json isDraft,targetCommitish --jq '[.isDraft, .targetCommitish] | @tsv')"; then
  draft="${existing%%$'\t'*}"
  target="${existing#*$'\t'}"
  if [[ "${draft}" != "true" ]]; then
    echo "Release ${RELEASE_TAG} is already published. Refusing to replace it." >&2
    exit 1
  fi
  if [[ "${target}" != "${GITHUB_SHA}" ]]; then
    echo "Draft ${RELEASE_TAG} points at ${target}, not ${GITHUB_SHA}. Refusing to replace it." >&2
    exit 1
  fi
  echo "Removing the unpublished draft ${RELEASE_TAG} before uploading the complete set."
  gh release delete "${RELEASE_TAG}" --yes
fi

version="${RELEASE_TAG#v}"
prerelease="$(node "${script_dir}/version.mjs" is-prerelease --tag "${RELEASE_TAG}")"
create_args=(
  release create "${RELEASE_TAG}"
  --draft
  --target "${GITHUB_SHA}"
  --title "TunnelDesk ${version}"
  --notes-file "${notes}"
)
if [[ "${prerelease}" == "true" ]]; then
  create_args+=(--prerelease --latest=false)
else
  create_args+=(--latest)
fi
create_args+=("${asset_files[@]}")
gh "${create_args[@]}"

view_json="$(mktemp)"
gh release view "${RELEASE_TAG}" --json isDraft,assets > "${view_json}"
node "${script_dir}/version.mjs" verify-draft \
  --root "${repo_root}" \
  --tag "${RELEASE_TAG}" \
  --json "${view_json}"
rm -f "${view_json}"

gh release edit "${RELEASE_TAG}" --draft=false
echo "Published ${RELEASE_TAG}."
