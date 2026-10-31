package egress

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestSSHToGitHub simulates an SSH connection attempt to github.com:22 with permissive config
func TestSSHToGitHub(t *testing.T) {
	// Setup a fake upstream that logs what it receives
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Upstream received: %s %s", r.Method, r.RequestURI)
		io.WriteString(w, "fake-upstream")
	}))
	t.Cleanup(upstream.Close)

	// Setup gateway with permissive config (port 22 allowed)
	cfg := Config{
		Allow: []string{"github.com", "*.github.com"},
		Ports: []int{443, 80, 22}, // Permissive: SSH enabled
	}

	// Mock DNS resolution for github.com
	cfg.Resolve = func(ctx context.Context, host string) ([]netipAddr, error) {
		t.Logf("Resolving host: %s", host)
		if strings.HasSuffix(host, "github.com") {
			// Use a test IP that would work
			return []netipAddr{mustAddr("140.82.112.3")}, nil
		}
		return nil, fmt.Errorf("unknown host: %s", host)
	}

	// Mock dialing to upstream (or /dev/null for SSH, since we won't actually SSH)
	cfg.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		t.Logf("Gateway dialing: %s %s", network, addr)
		// For testing, dial the fake upstream instead of the real destination
		d := &net.Dialer{Timeout: 5 * time.Second}
		return d.DialContext(ctx, network, upstream.Listener.Addr().String())
	}

	g, err := Start(cfg)
	if err != nil {
		t.Fatalf("Failed to start gateway: %v", err)
	}
	t.Cleanup(func() { g.Close() })

	t.Logf("Gateway listening on: %s", g.Addr())

	// Test 1: SSH to github.com:22 - should be ALLOWED in permissive mode
	t.Log("\n=== Test 1: SSH to github.com:22 (should be allowed) ===")
	c, err := net.Dial("tcp", g.Addr())
	if err != nil {
		t.Fatalf("Failed to connect to gateway: %v", err)
	}
	defer c.Close()

	// Send CONNECT request for SSH
	connectReq := "CONNECT github.com:22 HTTP/1.1\r\nHost: github.com:22\r\n\r\n"
	if _, err := io.WriteString(c, connectReq); err != nil {
		t.Fatalf("Failed to send CONNECT: %v", err)
	}

	// Read response
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}
	defer resp.Body.Close()

	t.Logf("Response: %s", resp.Status)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 OK for SSH in permissive mode, got %d %s", resp.StatusCode, resp.Status)
	}

	// Test 2: Try HTTPS to github.com:443 - should also work
	t.Log("\n=== Test 2: HTTPS to github.com:443 (should be allowed) ===")
	c2, err := net.Dial("tcp", g.Addr())
	if err != nil {
		t.Fatalf("Failed to connect to gateway: %v", err)
	}
	defer c2.Close()

	connectReq2 := "CONNECT github.com:443 HTTP/1.1\r\nHost: github.com:443\r\n\r\n"
	if _, err := io.WriteString(c2, connectReq2); err != nil {
		t.Fatalf("Failed to send CONNECT: %v", err)
	}

	br2 := bufio.NewReader(c2)
	resp2, err := http.ReadResponse(br2, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}
	defer resp2.Body.Close()

	t.Logf("Response: %s", resp2.Status)
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 OK for HTTPS, got %d %s", resp2.StatusCode, resp2.Status)
	}

	// Test 3: Try forbidden port (e.g., 8080)
	t.Log("\n=== Test 3: github.com:8080 (should be denied) ===")
	c3, err := net.Dial("tcp", g.Addr())
	if err != nil {
		t.Fatalf("Failed to connect to gateway: %v", err)
	}
	defer c3.Close()

	connectReq3 := "CONNECT github.com:8080 HTTP/1.1\r\nHost: github.com:8080\r\n\r\n"
	if _, err := io.WriteString(c3, connectReq3); err != nil {
		t.Fatalf("Failed to send CONNECT: %v", err)
	}

	br3 := bufio.NewReader(c3)
	resp3, err := http.ReadResponse(br3, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}
	defer resp3.Body.Close()

	t.Logf("Response: %s", resp3.Status)
	if resp3.StatusCode == http.StatusOK {
		t.Errorf("Expected rejection for port 8080, got %d", resp3.StatusCode)
	}
}

// TestSSHStrictVsPermissive directly compares behavior
func TestSSHStrictVsPermissive(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	t.Cleanup(upstream.Close)

	dialUpstream := func(ctx context.Context, n, addr string) (net.Conn, error) {
		d := &net.Dialer{Timeout: 5 * time.Second}
		return d.DialContext(ctx, n, upstream.Listener.Addr().String())
	}

	resolveGitHub := func(ctx context.Context, h string) ([]netipAddr, error) {
		return []netipAddr{mustAddr("140.82.112.3")}, nil
	}

	// Strict mode: port 22 NOT allowed
	t.Log("=== STRICT MODE (port 22 NOT allowed) ===")
	strictCfg := Config{
		Allow:   []string{"github.com"},
		Ports:   []int{443, 80}, // No SSH
		Resolve: resolveGitHub,
		Dial:    dialUpstream,
	}
	strictGW, err := Start(strictCfg)
	if err != nil {
		t.Fatalf("Failed to start strict gateway: %v", err)
	}
	t.Cleanup(func() { strictGW.Close() })

	c1, _ := net.Dial("tcp", strictGW.Addr())
	io.WriteString(c1, "CONNECT github.com:22 HTTP/1.1\r\nHost: github.com:22\r\n\r\n")
	br1 := bufio.NewReader(c1)
	resp1, _ := http.ReadResponse(br1, &http.Request{Method: http.MethodConnect})
	c1.Close()
	t.Logf("Strict mode SSH result: %s", resp1.Status)
	if resp1.StatusCode == http.StatusOK {
		t.Error("STRICT: Port 22 should be DENIED but got 200 OK")
	} else {
		t.Log("✓ STRICT: Port 22 correctly DENIED")
	}

	// Permissive mode: port 22 allowed
	t.Log("\n=== PERMISSIVE MODE (port 22 allowed) ===")
	permissiveCfg := Config{
		Allow:   []string{"github.com"},
		Ports:   []int{443, 80, 22}, // SSH allowed
		Resolve: resolveGitHub,
		Dial:    dialUpstream,
	}
	permGW, err := Start(permissiveCfg)
	if err != nil {
		t.Fatalf("Failed to start permissive gateway: %v", err)
	}
	t.Cleanup(func() { permGW.Close() })

	c2, _ := net.Dial("tcp", permGW.Addr())
	io.WriteString(c2, "CONNECT github.com:22 HTTP/1.1\r\nHost: github.com:22\r\n\r\n")
	br2 := bufio.NewReader(c2)
	resp2, _ := http.ReadResponse(br2, &http.Request{Method: http.MethodConnect})
	c2.Close()
	t.Logf("Permissive mode SSH result: %s", resp2.Status)
	if resp2.StatusCode != http.StatusOK {
		t.Error("PERMISSIVE: Port 22 should be ALLOWED but got", resp2.StatusCode)
	} else {
		t.Log("✓ PERMISSIVE: Port 22 correctly ALLOWED")
	}
}
