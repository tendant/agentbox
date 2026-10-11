// Package seatbelt is the public constructor for agentbox's macOS backend:
// sandbox-exec profiles, weaker than gVisor (see the backend's
// documentation and its Capabilities).
package seatbelt

import (
	"github.com/tendant/agentbox/internal/backend/seatbelt"
	"github.com/tendant/agentbox/pkg/agentbox"
)

// Config configures the backend; see the fields' documentation.
type Config = seatbelt.Config

// New returns the Seatbelt backend.
func New(cfg Config) agentbox.Backend { return seatbelt.New(cfg) }
