# SPDX-License-Identifier: Apache-2.0
#
# The CA key store — rung 3 of RM-147 (#238).
#
# FILE STORAGE AND NO DEV MODE. The store starts SEALED and stays sealed until
# an operator unseals it with a key that exists nowhere in this repository.
# #238: "A dev-mode store that unseals with a known key is theatre and must not
# be what ships."
#
# TLS IS DISABLED ON A NETWORK WITH TWO MEMBERS, which is the same trade
# sigstore.yml makes for Fulcio and Rekor and for the same reason: the transport
# here is a docker network the CA and the bootstrapper are the only members of,
# and a self-signed certificate that everything is configured to ignore is not
# more secure than no certificate — it is the same security with more moving
# parts. A deployment that puts this store off-box turns this on, and that is
# the one line it has to change.
ui = false

storage "file" {
  path = "/openbao/data"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

# NO `disable_mlock`, AND NOT BECAUSE IT DEFAULTS WELL. MEASURED on the pinned
# version: it refuses to start at all with the line present —
#
#   "OpenBao has dropped support for mlock. Please remove the line
#    disable_mlock = false from your config and disable or encrypt swap instead."
#
# So the protection that line used to buy has moved off this file and onto the
# host: a machine running this should have encrypted swap, and doc 05 §2 is
# where that belongs rather than in a config comment nobody reads. Written down
# here because the absence of a line is invisible, and the next person to add it
# back will get a store that will not boot with no idea why.

# No `default_lease_ttl` heroics: the CA's token is minted per start by
# `make innsegl-ca-custody-up` with its own TTL, and that is the lease that
# matters — it is what bounds a reader of the CA container.
