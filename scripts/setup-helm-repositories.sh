#!/usr/bin/env bash
set -euo pipefail

helm repo add trivy-operator https://aquasecurity.github.io/helm-charts/ --force-update
helm repo add kyverno https://kyverno.github.io/kyverno/ --force-update
helm repo add kubescape https://kubescape.github.io/helm-charts/ --force-update
helm repo update
