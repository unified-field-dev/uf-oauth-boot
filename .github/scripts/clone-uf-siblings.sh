#!/usr/bin/env bash
# Shallow-clone deathbreakfast path-dep / patch siblings into a Unified Field layout.
# Requires UF_CI_CLONE_TOKEN (PAT with read access to private deathbreakfast forks:
# lepton, gauge, neutrino, unified-field-product, lepton-uf-app, record-history, …).
# GITHUB_TOKEN alone cannot clone other private repos under the same user.
set -euo pipefail

: "${UF_ROOT:?UF_ROOT must be set (e.g. unified-field)}"

if [[ -z "${UF_CI_CLONE_TOKEN:-}" ]]; then
  echo "::error::Missing secret UF_CI_CLONE_TOKEN. Add a classic or fine-grained PAT with Contents: Read on private deathbreakfast siblings (at least lepton, gauge, neutrino, unified-field-product, lepton-uf-app), then: gh secret set UF_CI_CLONE_TOKEN --repo deathbreakfast/uf-oauth-boot"
  exit 1
fi

clone() {
  local repo="$1" dest="$2"
  git clone --depth 1 \
    "https://x-access-token:${UF_CI_CLONE_TOKEN}@github.com/deathbreakfast/${repo}.git" \
    "${dest}"
}

clone valence "${UF_ROOT}/L0-upstream-cores/valence"
clone orbital "${UF_ROOT}/L0-upstream-cores/orbital"
clone chronon "${UF_ROOT}/L0-upstream-cores/chronon"
clone photon "${UF_ROOT}/L0-upstream-cores/photon"
clone spectra "${UF_ROOT}/L0-upstream-cores/spectra"
clone higgs "${UF_ROOT}/L1-host-stack-kits/higgs"
clone lepton "${UF_ROOT}/L1-host-stack-kits/lepton"
clone chronon-coordinator "${UF_ROOT}/L1-host-stack-kits/chronon-coordinator"
clone chronon-coordinator-macros "${UF_ROOT}/L1-host-stack-kits/chronon-coordinator-macros"
clone chronon-valence-identity "${UF_ROOT}/L1-host-stack-kits/chronon-valence-identity"
clone photon-leptos "${UF_ROOT}/L1-host-stack-kits/photon-leptos"
clone unified-field-product "${UF_ROOT}/L2-product-platform/unified-field-product"
clone uf-notifications "${UF_ROOT}/L2-product-platform/uf-notifications"
clone record-history "${UF_ROOT}/L2-product-platform/record-history"
# Patch stanza may reference lepton-shell even when unused in this graph.
clone lepton-uf-app "${UF_ROOT}/L2-product-platform/lepton-uf-app"
clone gauge "${UF_ROOT}/L3-zone-products/gauge"
clone neutrino "${UF_ROOT}/L3-zone-products/neutrino"
