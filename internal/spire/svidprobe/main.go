// SPDX-License-Identifier: Apache-2.0

// Command svidprobe fetches the calling workload's own SVID from the SPIRE
// Workload API and prints the classified outcome as one line of JSON.
//
// It exists because the workload has to *be* a container. SPIRE attests the
// process on the other end of the socket — its uid, its binary, and the Docker
// metadata of the container it lives in — so a test running on the developer's
// machine cannot be an agent run, and one that pretended to be would be
// testing nothing. TC-SPI's integration cases therefore run this program inside
// a container carrying a run's selectors, and read the JSON back.
//
// It is deliberately the same client code the MCP and the agent runtime will
// use: internal/spire.FetchRunSVID does the fetch and the classification, so
// SPI-002's "ATTESTATION_FAILED, not retryable" is asserted about shipped code
// rather than about a line of test scaffolding.
//
// Exit status: 0 when an SVID was issued, 3 when it was refused, 2 on bad
// usage. The JSON is printed either way.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"innsegl.dev/innsegl/internal/spire"
)

func main() {
	os.Exit(run())
}

// run is main's body. main() itself only calls os.Exit, so that every deferred
// cancel in here actually runs.
func run() int {
	addr := flag.String("addr", spire.DefaultWorkloadAPIAddress, "Workload API address")
	trustDomain := flag.String("trust-domain", "innsegl.dev", "SPIFFE trust domain")
	agentType := flag.String("agent-type", "", "run's agent type")
	taskID := flag.String("task-id", "", "run's task id")
	runID := flag.String("run-id", "", "run's id")
	timeout := flag.Duration("timeout", 20*time.Second, "overall deadline")
	flag.Parse()

	if *agentType == "" || *taskID == "" || *runID == "" {
		fmt.Fprintln(os.Stderr, "svidprobe: -agent-type, -task-id and -run-id are required")
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	run := spire.RunRef{AgentType: *agentType, TaskID: *taskID, RunID: *runID}
	svid, err := spire.FetchRunSVID(ctx, *addr, *trustDomain, run)

	line, mErr := json.Marshal(spire.Outcome(svid, err))
	if mErr != nil {
		fmt.Fprintf(os.Stderr, "svidprobe: marshal outcome: %v\n", mErr)
		return 2
	}
	fmt.Println(string(line))

	if err != nil {
		return 3
	}
	return 0
}
