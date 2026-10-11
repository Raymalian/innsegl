// SPDX-License-Identifier: Apache-2.0

package deploytest

const (
	DashboardContainerPort = 8082
	// DashboardTLSContainerPort is the dashboard over HTTPS at the core's
	// name (RM-311, #493), exposed with the plain port.
	DashboardTLSContainerPort = 8443
	BindDocAddr               = "192.0.2.10"
)
