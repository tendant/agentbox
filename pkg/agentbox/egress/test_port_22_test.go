package egress

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestPort22WithPermissiveConfig ensures port 22 is allowed when configured
func TestPort22WithPermissiveConfig(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "upstream-ok") }))
	t.Cleanup(up.Close)

	cfg := Config{
		Allow: []string{"*"},
		Ports: []int{443, 80, 22}, // Permissive: include SSH
	}
	cfg.Resolve = func(_ context.Context, h string) ([]netipAddr, error) {
		return []netipAddr{mustAddr("1.1.1.1")}, nil
	}
	cfg.Dial = func(ctx context.Context, n, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, n, up.Listener.Addr().String())
	}

	g, err := Start(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { g.Close() })

	// Test SSH connection to example.com:22 - should succeed
	c, err := net.Dial("tcp", g.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := io.WriteString(c, "CONNECT example.com:22 HTTP/1.1\r\nHost: example.com:22\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	br := &http.Request{Method: http.MethodConnect}
	resp, err := http.ReadResponse(bufio.NewReader(c), br)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Port 22 with permissive config should be allowed (200 OK), got %d", resp.StatusCode)
	}
}

// TestPort22WithStrictConfig ensures port 22 is blocked in strict mode
func TestPort22WithStrictConfig(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "upstream-ok") }))
	t.Cleanup(up.Close)

	cfg := Config{
		Allow: []string{"*"},
		Ports: []int{443, 80}, // Strict: no SSH
	}
	cfg.Resolve = func(_ context.Context, h string) ([]netipAddr, error) {
		return []netipAddr{mustAddr("1.1.1.1")}, nil
	}
	cfg.Dial = func(ctx context.Context, n, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, n, up.Listener.Addr().String())
	}

	g, err := Start(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { g.Close() })

	// Test SSH connection to example.com:22 - should be denied
	c, err := net.Dial("tcp", g.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := io.WriteString(c, "CONNECT example.com:22 HTTP/1.1\r\nHost: example.com:22\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode == http.StatusOK {
		t.Errorf("Port 22 with strict config should be denied, got %d", resp.StatusCode)
	}
	if !strings.Contains(resp.Status, "403") && !strings.Contains(resp.Status, "Forbidden") {
		t.Logf("Got status: %s", resp.Status)
	}
}
