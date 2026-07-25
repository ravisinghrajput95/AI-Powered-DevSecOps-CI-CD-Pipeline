#!/usr/bin/env bash
# Generate the behaviour the KubeArmor audit policies watch for, so the
# capture window has something to capture.
#
# Why this exists
# ---------------
# KubeArmor records what happens while its capture window is open. CloudCart
# in steady state serves HTTP and does nothing else — it never execs a shell,
# never reads /etc/shadow, never runs curl. So the window closed empty on
# every run and the runtime domain reported NO_SIGNAL.
#
# That was read for a long time as KubeArmor being broken on GKE/COS, and it
# is not: a manual `karmor logs` capture with a shell exec against the same
# cluster produces the expected alert immediately, with the right policy name,
# severity and MITRE tag. The tool works. The window was simply idle.
#
# This is the same model ZAP uses for DAST — you do not learn whether runtime
# detection works by watching an idle app, you learn it by performing the
# actions you claim to detect and confirming they are detected.
#
# Honesty note
# ------------
# Findings produced from this are SIMULATED adversary behaviour, not an
# observed intrusion. They demonstrate that detection works. Nothing here
# should be read as evidence that CloudCart was attacked.
#
# Only process-based triggers are used. File-path policies did not produce
# alerts in manual testing on this cluster (2026-07-25, GKE 1.35 / COS /
# containerd 2.1.7), and one of them cannot: the serviceaccount token is a
# symlink to ..data/token, and KubeArmor matches resolved paths. Rather than
# generate activity that reliably produces nothing, this sticks to the path
# proven to work end to end. See helm/bootstrap/README.md.
set -uo pipefail

NAMESPACE="${NAMESPACE:-cloudcart}"

# Shell execution inside an application container is the signal worth
# demonstrating: it is what command injection looks like after the fact, and
# every one of these policies is tagged MITRE-T1059.
exercise_pod() {
  local pod="$1" container="$2"
  local target="-n ${NAMESPACE} ${pod}"
  [ -n "${container}" ] && target="${target} -c ${container}"

  # shellcheck disable=SC2086
  kubectl exec ${target} -- /bin/sh -c 'id > /dev/null 2>&1' >/dev/null 2>&1 \
    && echo "  triggered /bin/sh in ${pod}" \
    || echo "  /bin/sh unavailable in ${pod} (skipped)"

  # shellcheck disable=SC2086
  kubectl exec ${target} -- /bin/bash -c 'id > /dev/null 2>&1' >/dev/null 2>&1 \
    && echo "  triggered /bin/bash in ${pod}" \
    || echo "  /bin/bash unavailable in ${pod} (skipped)"
}

echo "Exercising KubeArmor audit policies in namespace ${NAMESPACE}"

triggered=0
for selector in "app=cloudcart-backend:backend" "app=cloudcart-frontend:" ; do
  labels="${selector%%:*}"
  container="${selector##*:}"
  pods=$(kubectl get pods -n "${NAMESPACE}" -l "${labels}" \
           --field-selector=status.phase=Running \
           -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)
  if [ -z "${pods}" ]; then
    echo "  no Running pods for ${labels} (skipped)"
    continue
  fi
  for pod in ${pods}; do
    exercise_pod "${pod}" "${container}"
    triggered=$((triggered + 1))
  done
done

# Alert throttling is on (maxAlertPerSec 10, throttleSec 30), so repeating the
# same action in a tight loop yields one alert, not many. A second pass after
# the throttle interval is deliberately NOT done — the capture window is 30s
# and the goal is proof of detection, not volume.

if [ "${triggered}" -eq 0 ]; then
  echo "::warning::no pods were exercised — the runtime domain will report NO_SIGNAL"
  exit 1
fi

echo "Exercised ${triggered} pod(s)"
