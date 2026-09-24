// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"innsegl.dev/innsegl/internal/event"
)

// ADOPTION'S PROOF — ADR-0051 decision 2, #298 (RM-187).
//
// A live run may commit work a dead run left, and the commit names both. What
// makes that a record rather than a claim is this file: for every path handed
// over, the bytes are rebuilt from the dead run's OWN tool-call bodies, each
// read back and checked against the digest the chain holds for it. The caller
// supplies nothing that enters the proof except the list of paths.
//
// WHAT COUNTS AS WRITING A PATH. A `Write` body carries the whole content. An
// `Edit` body carries, in its response, the file as it was before the edit and
// the replacement made, so replaying the one edit gives the whole file after
// it. Either way the LAST such call on a path is the bytes the run left there.
// A path written through a shell has no body that names its bytes, and is
// refused rather than adopted on trust.
//
// STRICT ON A BAD BODY. One `Write` or `Edit` body that is missing or does not
// match its digest refuses the whole adoption, not just its path. The body
// cannot be read, so which path it touched cannot be known either — and an
// adoption that silently fell back to an earlier call for that path would be
// proving the wrong bytes.

// adoptedPath is one path's proof: the bytes the dead run left, their SHA-256,
// and the event_hash of the tool call that produced them.
type adoptedPath struct {
	Path     string
	Bytes    []byte
	SHA256   string
	ToolCall string
}

// adoptBody is the part of a stored tool-call body the proof reads.
type adoptBody struct {
	ToolName  string `json:"tool_name"`
	ToolInput struct {
		FilePath string `json:"file_path"`
		Content  string `json:"content"`
	} `json:"tool_input"`
	ToolResponse struct {
		OriginalFile string `json:"originalFile"`
		OldString    string `json:"oldString"`
		NewString    string `json:"newString"`
		ReplaceAll   bool   `json:"replaceAll"`
	} `json:"tool_response"`
}

// rebuildLeftBytes returns, for every staged path, the bytes runID's last
// Write or Edit left there, or an error naming what could not be proved.
func rebuildLeftBytes(events []event.Fields, bodyDir, runID string, staged []string) (map[string]adoptedPath, error) {
	type call struct {
		file  string
		bytes []byte
		hash  string
	}
	var calls []call
	var bad []string
	for _, ev := range events {
		if ev[event.FieldEventType] != event.EventTypeToolCall || ev[event.FieldRunID] != runID {
			continue
		}
		tool := fieldString(ev, event.FieldToolName)
		if tool != "Write" && tool != "Edit" {
			continue
		}
		hash := fieldString(ev, event.EventHashField)
		digest := fieldString(ev, event.FieldPayloadDigest)
		raw, err := os.ReadFile(filepath.Join(bodyDir, filepath.Base(runID),
			strings.TrimPrefix(digest, event.HashPrefix)+observeBodyExt))
		if err != nil {
			bad = append(bad, fmt.Sprintf("the body of %s %s cannot be read", tool, hash))
			continue
		}
		if event.Digest(raw) != digest {
			bad = append(bad, fmt.Sprintf("the body of %s %s does not match its digest", tool, hash))
			continue
		}
		var b adoptBody
		if err = json.Unmarshal(raw, &b); err != nil {
			bad = append(bad, fmt.Sprintf("the body of %s %s is not a tool call", tool, hash))
			continue
		}
		left, err := leftBy(tool, b)
		if err != nil {
			bad = append(bad, fmt.Sprintf("%s %s on %s cannot be replayed: %v", tool, hash, b.ToolInput.FilePath, err))
			continue
		}
		calls = append(calls, call{file: b.ToolInput.FilePath, bytes: left, hash: hash})
	}

	out := make(map[string]adoptedPath, len(staged))
	top := ""
	var unproved []string
	for _, path := range staged {
		found := false
		for i := len(calls) - 1; i >= 0; i-- {
			c := calls[i]
			if !strings.HasSuffix(c.file, "/"+path) {
				continue
			}
			here := strings.TrimSuffix(c.file, "/"+path)
			if top == "" {
				top = here
			}
			if here != top {
				continue
			}
			out[path] = adoptedPath{Path: path, Bytes: c.bytes,
				SHA256: strings.TrimPrefix(event.Digest(c.bytes), event.HashPrefix), ToolCall: c.hash}
			found = true
			break
		}
		if !found {
			unproved = append(unproved, path)
		}
	}
	if len(unproved) == 0 && len(bad) == 0 {
		return out, nil
	}
	sort.Strings(unproved)
	msg := ""
	if len(unproved) > 0 {
		msg = fmt.Sprintf("no Write or Edit by %s in %s proves %s", runID, orUnknown(top),
			strings.Join(unproved, ", "))
	}
	if len(bad) > 0 {
		if msg != "" {
			msg += "; and "
		}
		msg += strings.Join(bad, "; ")
	}
	return nil, fmt.Errorf("%s", msg)
}

// leftBy is the whole file one call left behind.
func leftBy(tool string, b adoptBody) ([]byte, error) {
	if tool == "Write" {
		return []byte(b.ToolInput.Content), nil
	}
	r := b.ToolResponse
	n := strings.Count(r.OriginalFile, r.OldString)
	switch {
	case r.OldString == "" || n == 0:
		return nil, fmt.Errorf("its old string is not in the file it edited")
	case r.ReplaceAll:
		return []byte(strings.ReplaceAll(r.OriginalFile, r.OldString, r.NewString)), nil
	case n > 1:
		return nil, fmt.Errorf("its old string occurs %d times and it did not replace all", n)
	}
	return []byte(strings.Replace(r.OriginalFile, r.OldString, r.NewString, 1)), nil
}

// fieldString is one string member of an event, or "" when it is absent or
// not a string. Every member read here is a string in doc 02.
func fieldString(ev event.Fields, key string) string {
	v, ok := ev[key].(string)
	if !ok {
		return ""
	}
	return v
}

func orUnknown(top string) string {
	if top == "" {
		return "any checkout"
	}
	return top
}
