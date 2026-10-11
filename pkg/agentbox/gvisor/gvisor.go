// Package gvisor is the public constructor for agentbox's gVisor backend:
// rootless runsc driven directly, Linux only.
package gvisor

import (
	"github.com/tendant/agentbox/internal/backend/gvisor"
	"github.com/tendant/agentbox/pkg/agentbox"
)

// Config configures the backend; see the fields' documentation.
type Config = gvisor.Config

// New returns the gVisor backend.
func New(cfg Config) agentbox.Backend { return gvisor.New(cfg) }
