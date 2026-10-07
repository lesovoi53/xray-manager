package cupsonline

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"openflux/transport"
)

const fixtureRoomA = "00000000-0000-0000-0000-000000000001"
const fixtureRoomB = "00000000-0000-0000-0000-000000000002"

func fixtureRoomList(ids ...string) string {
	raw, _ := json.Marshal(ids)
	return base64.RawURLEncoding.EncodeToString(raw)
}

type roomRoundTrip func(*http.Request) (*http.Response, error)

func (f roomRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Exercise real authorize and Start without external I/O. The WebSocket URL
// has an unsupported scheme, so worker goroutines cannot dial any host.
func stubRoomHTTP(t *testing.T, wrongRoom bool) *[]string {
	t.Helper()
	var gets []string
	previous := http.DefaultTransport
	http.DefaultTransport = roomRoundTrip(func(r *http.Request) (*http.Response, error) {
		body := `{"token":"fixture-sub-token"}`
		header := make(http.Header)
		if r.Method == http.MethodGet {
			id := r.URL.Query().Get("room")
			gets = append(gets, id)
			if id == "" || wrongRoom {
				id = fixtureRoomB
			}
			body = fmt.Sprintf(`<meta name="centrifuge-connection-token" content="fixture-connection-token"><meta name="centrifuge-connection-url" content="invalid://fixture"><meta name="centrifuge-subscription-token-url" content="https://interview.cups.online/fixture-token"><div data-room="{&quot;uuid&quot;: &quot;%s&quot;}" data-user="{&quot;uuid&quot;: &quot;%s&quot;}"></div>`, id, fixtureRoomB)
			header.Set("Set-Cookie", "csrftoken=fixture; Path=/")
		}
		return &http.Response{StatusCode: 200, Header: header, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})
	t.Cleanup(func() { http.DefaultTransport = previous })
	return &gets
}

func TestCupsonlineExplicitRoomsSurviveExitRestart(t *testing.T) {
	for _, client := range []bool{false, true} {
		for _, form := range []string{baseRoomURL + "?room=" + fixtureRoomA,
			baseRoomURL + "?rooms=" + fixtureRoomList(fixtureRoomA, fixtureRoomB),
			fixtureRoomList(fixtureRoomA, fixtureRoomB)} {
			t.Run(fmt.Sprintf("client=%v/form=%d", client, len(form)), func(t *testing.T) {
				gets := stubRoomHTTP(t, false)
				want := []string{fixtureRoomA, fixtureRoomB}
				if strings.Contains(form, "?room=") {
					want = want[:1]
				}
				// Construct twice like a service restart; neither instance may
				// silently create a fresh room or change the requested direction.
				for restart := 0; restart < 2; restart++ {
					tr := NewCupsonlineTransport(form, transport.DefaultConfig(), client)
					tr.config.NumRooms, tr.config.RoomCreatePause = 1, time.Nanosecond
					if tr.isClient != client {
						t.Fatal("role changed")
					}
					if err := tr.Start(); err != nil {
						t.Fatal(err)
					}
					got := tr.RoomUUIDs()
					_ = tr.Stop()
					if !reflect.DeepEqual(got, want) {
						t.Fatalf("configured rooms changed: got %v want %v", got, want)
					}
				}
				if !reflect.DeepEqual(*gets, append(append([]string{}, want...), want...)) {
					t.Fatal("Start did not request exactly the configured rooms")
				}
			})
		}
	}
}

func TestCupsonlineInvalidExplicitRoomsFailBeforeHTTP(t *testing.T) {
	for _, raw := range []string{"not-a-room", baseRoomURL, baseRoomURL + "?rooms=invalid",
		baseRoomURL + "?room=bad&injected=true", fixtureRoomList(), fixtureRoomList(""),
		fixtureRoomList(fixtureRoomA, fixtureRoomA)} {
		for _, client := range []bool{false, true} {
			t.Run(fmt.Sprintf("client=%v/raw=%s", client, raw), func(t *testing.T) {
				gets := stubRoomHTTP(t, false)
				tr := NewCupsonlineTransport(raw, transport.DefaultConfig(), client)
				tr.config.NumRooms, tr.config.RoomCreatePause = 1, time.Nanosecond
				err := tr.Start()
				_ = tr.Stop()
				if err == nil || len(*gets) != 0 {
					t.Fatal("invalid explicit rooms must fail before any HTTP request")
				}
			})
		}
	}
}

func TestCupsonlineExplicitRoomRejectsServerReplacement(t *testing.T) {
	for _, client := range []bool{false, true} {
		t.Run(fmt.Sprint(client), func(t *testing.T) {
			stubRoomHTTP(t, true)
			tr := NewCupsonlineTransport(baseRoomURL+"?room="+fixtureRoomA, transport.DefaultConfig(), client)
			tr.config.NumRooms, tr.config.RoomCreatePause = 1, time.Nanosecond
			err := tr.Start()
			_ = tr.Stop()
			if err == nil || len(tr.RoomUUIDs()) != 0 {
				t.Fatal("replacement room was accepted")
			}
		})
	}
}

func TestCupsonlineEmptyExitKeepsAutocreate(t *testing.T) {
	gets := stubRoomHTTP(t, false)
	tr := NewCupsonlineTransport("", transport.DefaultConfig(), false)
	tr.config.NumRooms, tr.config.RoomCreatePause = 1, time.Nanosecond
	if err := tr.Start(); err != nil {
		t.Fatal(err)
	}
	_ = tr.Stop()
	if !reflect.DeepEqual(*gets, []string{""}) || len(tr.RoomUUIDs()) != 1 || tr.isClient {
		t.Fatal("empty exit URL no longer selects legacy creation")
	}
}

func TestCupsonlinePartialExplicitSetFailsClosed(t *testing.T) {
	for _, client := range []bool{false, true} {
		t.Run(fmt.Sprint(client), func(t *testing.T) {
			stubRoomHTTP(t, false)
			inner := http.DefaultTransport
			http.DefaultTransport = roomRoundTrip(func(r *http.Request) (*http.Response, error) {
				if r.Method == http.MethodGet && r.URL.Query().Get("room") == fixtureRoomB {
					return &http.Response{StatusCode: 404, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
				}
				return inner.RoundTrip(r)
			})
			tr := NewCupsonlineTransport(fixtureRoomList(fixtureRoomA, fixtureRoomB), transport.DefaultConfig(), client)
			err := tr.Start()
			_ = tr.Stop()
			if err == nil || len(tr.RoomUUIDs()) != 0 || len(tr.wss) != 0 {
				t.Fatal("partial configured room set was activated")
			}
		})
	}
}
