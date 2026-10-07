package yandex

import (
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"openflux/transport"
)

// Real TLS/WebSocket integration through connectAndServe and its actual timers.
// In Engine.IO v4 the server sends 2 (ping) and the client answers 3 (pong).
// Waiting past the real 20s interval catches the original client-ping defect.
func TestBoardsEIO4HeartbeatDirectionAndData(t *testing.T) {
	result := make(chan error, 1)
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	inbound := []byte("fixture-inbound-packet")
	outbound := []byte("fixture-outbound-packet")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("EIO") != "4" {
			result <- fmt.Errorf("transport did not request EIO4")
			return
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			result <- err
			return
		}
		defer conn.Close()
		exchange := func(send, expect string) error {
			if err := conn.WriteMessage(websocket.TextMessage, []byte(send)); err != nil {
				return err
			}
			_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			_, got, err := conn.ReadMessage()
			if err != nil {
				return err
			}
			if !strings.Contains(string(got), expect) {
				return fmt.Errorf("unexpected handshake frame; wanted %s", expect)
			}
			return nil
		}
		if err := exchange(`0{"sid":"fixture","upgrades":[],"pingInterval":25000,"pingTimeout":30000}`, "40"); err != nil {
			result <- err
			return
		}
		if err := exchange(`40{"sid":"fixture"}`, `"im"`); err != nil {
			result <- err
			return
		}
		if err := exchange(`42["im",{"subscribed":true}]`, "subscribe-slide-dashboard"); err != nil {
			result <- err
			return
		}
		for _, frame := range []string{
			`431[{"participant":{"dashboard_link":{"session":"fixture","dashboard":"fixture-slide"}}}]`,
			"2",
			fmt.Sprintf(`42["dashboard",{"action":"notify-position","participant":"fixture-peer","data":{"position":{"x":%q,"y":123}}}]`, base64.StdEncoding.EncodeToString(inbound)),
		} {
			if err := conn.WriteMessage(websocket.TextMessage, []byte(frame)); err != nil {
				result <- err
				return
			}
		}
		pong, dashboardHeartbeat, data := false, false, false
		_ = conn.SetReadDeadline(time.Now().Add(boardsPingInterval + time.Second))
		for {
			_, raw, err := conn.ReadMessage()
			if err != nil {
				if timeout, ok := err.(net.Error); ok && timeout.Timeout() && pong && dashboardHeartbeat && data {
					result <- nil
				} else {
					result <- fmt.Errorf("session ended: pong=%v dashboard-heartbeat=%v data=%v error=%v", pong, dashboardHeartbeat, data, err)
				}
				return
			}
			frame := string(raw)
			if frame == "2" {
				result <- fmt.Errorf("invalid EIO4 heartbeat direction: client sent unsolicited ping 2")
				return
			}
			pong = pong || frame == "3"
			dashboardHeartbeat = dashboardHeartbeat || strings.Contains(frame, `"action":"heartbeat"`)
			data = data || strings.Contains(frame, base64.StdEncoding.EncodeToString(outbound))
		}
	}))
	defer server.Close()

	// Trust only this loopback fixture certificate for this test. The production
	// transport's TLS verification remains enabled and its dialer is unmodified.
	certFile := filepath.Join(t.TempDir(), "fixture-ca.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", certFile)
	t.Setenv("SSL_CERT_DIR", t.TempDir())
	tr := NewBoardsTransport("fixture", transport.DefaultConfig())
	if err := tr.BaseTransport.Start(); err != nil {
		t.Fatal(err)
	}
	defer tr.Stop()
	packets := make(chan []byte, 1)
	tr.Receive(func(packet []byte) { packets <- packet })
	clientDone := make(chan error, 1)
	go func() {
		clientDone <- tr.connectAndServe(boardsInfo{wsHost: strings.TrimPrefix(server.URL, "https://"),
			userHash: "fixture-self", name: "fixture-self", dashboard: "fixture-slide", currentSlide: "fixture-slide"})
	}()
	select {
	case got := <-packets:
		if string(got) != string(inbound) {
			t.Fatal("inbound packet changed")
		}
	case err := <-clientDone:
		t.Fatalf("connectAndServe failed before data: %v", err)
	case err := <-result:
		t.Fatalf("mock handshake failed: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("inbound packet timeout")
	}
	if err := tr.Send(outbound); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(boardsPingInterval + 5*time.Second):
		t.Fatal("heartbeat observation timed out")
	}
}
