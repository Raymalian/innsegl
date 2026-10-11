#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# update-signing.sh: `make update` proves the CA can sign (OPS-190, OPS-191, #587).
#
#   scripts/update-signing.sh before   the probe, before the update touches anything
#   scripts/update-signing.sh after    the probe, once the services are up
#
# WHY. An update can leave every service healthy and the CA unable to sign.
# The probe is the core's one-shot `innsegl signing-probe` (exit 0 ok, 35
# failing, 36 could not be set up), run with `docker exec` into <prefix>-mcp,
# so it works for a live and a dev stack alike.
#
# before: never fails the update. A failing probe is reported first, so the
#   update is not blamed for an outage it found. Exits with the probe's own code.
# after:  exit 1 when the probe fails or cannot be set up; the reason and the
#   one repair line are printed. INNSEGL_SIGNING_BEFORE=<code> (the `before`
#   exit code) makes a failure say it predates the update.
#
# Settings: INNSEGL_STACK_PREFIX (default innsegl), INNSEGL_CA_CUSTODY=on
# (the repair is then the unlock on the operator machine).
set -u

mode=${1:-}
case "$mode" in before | after) ;; *)
	echo "usage: update-signing.sh before|after" >&2
	exit 2
	;;
esac

core="${INNSEGL_STACK_PREFIX:-innsegl}-mcp"
say() { echo "signing: $*"; }

if ! docker inspect -f '{{.State.Running}}' "$core" 2>/dev/null | grep -qx true; then
	if [ "$mode" = before ]; then
		say "not checked before the update ($core is not running)"
		exit 0
	fi
	say "FAILING - $core is not running, so signing cannot be checked"
	exit 1
fi

if [ -z "$(docker exec "$core" printenv INNSEGL_FULCIO_URL 2>/dev/null)" ]; then
	say "not configured on this stack (no Fulcio); not checked"
	exit 0
fi

out=$(docker exec "$core" innsegl signing-probe 2>&1)
rc=$?

repair() {
	if [ "${INNSEGL_CA_CUSTODY:-}" = on ]; then
		echo "repair: on the operator machine, run: innsegl ca-custody unlock"
	else
		echo "repair: see runbooks/ca-custody.md, section 3 (After a restart); once 'innsegl doctor' exists, run it on the operator machine"
	fi
}

if [ "$mode" = before ]; then
	case $rc in
	0) echo "$out" ;;
	36)
		say "the probe could not be set up before the update: $out"
		;;
	*)
		say "was already failing before the update; the update did not cause it."
		echo "$out"
		repair
		;;
	esac
	exit $rc
fi

case $rc in
0)
	echo "$out"
	exit 0
	;;
36)
	say "the probe could not be set up after the update (exit 36), so signing is unproven:"
	echo "$out"
	echo "repair: check the core's SPIRE credential and settings: docker logs $core"
	;;
*)
	say "FAILING after the update (probe exit $rc):"
	echo "$out"
	repair
	;;
esac
if [ -n "${INNSEGL_SIGNING_BEFORE:-}" ] && [ "${INNSEGL_SIGNING_BEFORE:-0}" != 0 ]; then
	say "it was already failing before the update (exit $INNSEGL_SIGNING_BEFORE): not caused by this update"
fi
exit 1
