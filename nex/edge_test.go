package nex

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	nex "github.com/PretendoNetwork/nex-go/v2"
	"github.com/PretendoNetwork/nex-go/v2/constants"
	"github.com/PretendoNetwork/nex-go/v2/types"

	"github.com/PretendoNetwork/wiiu-chat/globals"
)

type edgeRig struct {
	server *nex.PRUDPServer
	ep     *nex.PRUDPEndPoint
	edge   *httptest.Server // this package's edge endpoints
	hub    *httptest.Server // stands in for relayhub's /wuc-edge/out

	mu      sync.Mutex
	seen    []edgeSeenRequest // what the protocol handlers received
	posted  []hubPost         // what reached the hub
	logs    []string
	ended   int
	hubCode int // forced status of the hub's answer (0 = 204)
}

type edgeSeenRequest struct {
	proto  uint16
	call   uint32
	method uint32
	params []byte
	pid    uint64
}

type hubPost struct {
	Relay   string `json:"relay"`
	PID     uint32 `json:"pid"`
	Payload []byte `json:"payload"`
}

func newEdgeRig(t *testing.T) *edgeRig {
	t.Helper()
	r := &edgeRig{}
	r.server = nex.NewPRUDPServer()
	r.ep = nex.NewPRUDPEndPoint(1)
	r.ep.IsSecureEndPoint = true
	r.ep.ServerAccount = nex.NewAccount(types.NewPID(2), "Quazal Rendez-Vous", "pw", false)
	r.server.BindPRUDPEndPoint(r.ep)
	globals.SecureServer, globals.SecureEndpoint = r.server, r.ep

	// A protocol handler that answers every request with "pong", the way the protocol library does.
	r.ep.OnData(func(p nex.PacketInterface) {
		req := p.RMCMessage()
		conn := p.Sender().(*nex.PRUDPConnection)
		r.mu.Lock()
		r.seen = append(r.seen, edgeSeenRequest{req.ProtocolID, req.CallID, req.MethodID, req.Parameters, uint64(conn.PID())})
		r.mu.Unlock()
		resp := nex.NewRMCSuccess(r.ep, []byte("pong"))
		resp.ProtocolID, resp.CallID, resp.MethodID = req.ProtocolID, req.CallID, req.MethodID
		pkt, _ := nex.NewPRUDPPacketV1(r.server, conn, nil)
		pkt.SetType(constants.DataPacket)
		pkt.AddFlag(constants.PacketFlagNeedsAck)
		pkt.AddFlag(constants.PacketFlagReliable)
		pkt.SetPayload(resp.Bytes())
		r.server.Send(pkt)
	})
	r.ep.OnConnectionEnded(func(*nex.PRUDPConnection) { r.mu.Lock(); r.ended++; r.mu.Unlock() })

	r.hub = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var p hubPost
		json.NewDecoder(req.Body).Decode(&p)
		r.mu.Lock()
		r.posted = append(r.posted, p)
		code := r.hubCode
		r.mu.Unlock()
		if code == 0 {
			code = http.StatusNoContent
		}
		w.WriteHeader(code)
	}))
	r.edge = httptest.NewServer(edgeMux())

	oldHub := edgeHubURL
	edgeHubURL = r.hub.URL
	oldLog := setEdgeLogf(func(f string, a ...any) { r.mu.Lock(); r.logs = append(r.logs, fmt.Sprintf(f, a...)); r.mu.Unlock() })
	t.Cleanup(func() {
		// Stop every session's goroutine before restoring the globals it may still read.
		edgeSessions.Range(func(k, v any) bool {
			s := v.(*edgeSession)
			edgeSessions.Delete(k)
			s.end()
			select {
			case <-s.stopped:
			case <-time.After(2 * time.Second):
			}
			return true
		})
		r.edge.Close()
		r.hub.Close()
		edgeHubURL = oldHub
		setEdgeLogf(oldLog)
	})
	return r
}

func (r *edgeRig) post(path string, v any) int {
	b, _ := json.Marshal(v)
	resp, err := http.Post(r.edge.URL+path, "application/json", bytes.NewReader(b))
	if err != nil {
		return 0
	}
	resp.Body.Close()
	return resp.StatusCode
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (r *edgeRig) open(t *testing.T, relay string, pid uint32, port int) {
	t.Helper()
	if c := r.post("/edge/open", map[string]any{"relay": relay, "pid": pid, "ip": "203.0.113.7", "port": port}); c != http.StatusNoContent {
		t.Fatalf("open: %d", c)
	}
}

func TestEdgeSessionLifecycleRunsTheRealHandlersAndReturnsTheirReplies(t *testing.T) {
	r := newEdgeRig(t)
	r.open(t, "us-1", 42, 51234)

	// The player is an ordinary connection to everything that looks players up (notifications, NAT
	// traversal), with the address the relay saw.
	conn := r.ep.FindConnectionByPID(42)
	if conn == nil || conn.OutHook == nil || conn.Socket.Address.String() != "203.0.113.7:51234" {
		t.Fatalf("connection not registered as expected: %+v", conn)
	}

	// A request from the relay reaches the endpoint's handlers as if it came off the socket.
	if c := r.post("/edge/rmc", map[string]any{"relay": "us-1", "pid": 42, "call": 9, "proto": 0x1234, "method": 7, "params": []byte{1, 2, 3}}); c != http.StatusNoContent {
		t.Fatalf("rmc: %d", c)
	}
	waitFor(t, "the handler to run", func() bool { r.mu.Lock(); defer r.mu.Unlock(); return len(r.seen) == 1 })
	got := r.seen[0]
	if got.proto != 0x1234 || got.call != 9 || got.method != 7 || !bytes.Equal(got.params, []byte{1, 2, 3}) || got.pid != 42 {
		t.Fatalf("the handler saw %+v", got)
	}

	// Its reply went to the hub (not a socket), as the plain RMC message, tagged with the relay.
	waitFor(t, "the reply to reach the hub", func() bool { r.mu.Lock(); defer r.mu.Unlock(); return len(r.posted) == 1 })
	want := nex.NewRMCSuccess(r.ep, []byte("pong"))
	want.ProtocolID, want.CallID, want.MethodID = 0x1234, 9, 7
	if p := r.posted[0]; p.Relay != "us-1" || p.PID != 42 || !bytes.Equal(p.Payload, want.Bytes()) {
		t.Fatalf("hub received %+v, want the pong response (%x)", p, want.Bytes())
	}

	// Closing removes the connection and fires the connection-ended handlers (the chat logic's cleanup).
	if c := r.post("/edge/close", map[string]any{"relay": "us-1", "pid": 42}); c != http.StatusNoContent {
		t.Fatalf("close: %d", c)
	}
	if r.ep.FindConnectionByPID(42) != nil {
		t.Fatal("the connection is still registered after close")
	}
	r.mu.Lock()
	ended := r.ended
	r.mu.Unlock()
	if ended != 1 {
		t.Fatalf("connection-ended handlers ran %d times, want 1", ended)
	}
}

func TestOnlyDataPacketsAreDeliveredToTheRelay(t *testing.T) {
	r := newEdgeRig(t)
	r.open(t, "us-1", 5, 1000)
	conn := r.ep.FindConnectionByPID(5)
	ping, _ := nex.NewPRUDPPacketV1(r.server, conn, nil)
	ping.SetType(constants.PingPacket)
	ping.SetPayload([]byte("not an rmc message"))
	r.server.Send(ping)
	time.Sleep(100 * time.Millisecond)
	r.mu.Lock()
	n := len(r.posted)
	r.mu.Unlock()
	if n != 0 {
		t.Fatalf("a non-data packet was delivered to the relay (%d posts)", n)
	}
}

func TestARelayCanOnlyTouchItsOwnPlayers(t *testing.T) {
	r := newEdgeRig(t)
	r.open(t, "us-1", 42, 1000)
	for _, path := range []string{"/edge/rmc", "/edge/close", "/edge/stats", "/edge/trace"} {
		if c := r.post(path, map[string]any{"relay": "eu-9", "pid": 42, "proto": 1, "method": 1}); c != http.StatusConflict {
			t.Errorf("%s from another relay: %d, want 409", path, c)
		}
	}
	if r.ep.FindConnectionByPID(42) == nil {
		t.Fatal("another relay's close removed the session")
	}
	if c := r.post("/edge/rmc", map[string]any{"relay": "us-1", "pid": 999, "proto": 1, "method": 1}); c != http.StatusConflict {
		t.Errorf("rmc for an unknown pid: %d", c)
	}
}

func TestAReconnectReplacesTheOldSession(t *testing.T) {
	r := newEdgeRig(t)
	r.open(t, "us-1", 42, 1000)
	first := r.ep.FindConnectionByPID(42)
	r.open(t, "us-1", 42, 2000)
	second := r.ep.FindConnectionByPID(42)
	if second == nil || second == first || second.Socket.Address.String() != "203.0.113.7:2000" {
		t.Fatalf("the new session did not replace the old one: %+v", second)
	}
	r.mu.Lock()
	ended := r.ended
	r.mu.Unlock()
	if ended != 1 {
		t.Fatalf("the replaced session ended %d times, want 1", ended)
	}
}

func TestSessionsTheHubNoLongerKnowAreReleased(t *testing.T) {
	r := newEdgeRig(t)
	r.mu.Lock()
	r.hubCode = http.StatusNotFound // the hub restarted: it knows no relay holding the player
	r.mu.Unlock()
	r.open(t, "us-1", 42, 1000)
	conn := r.ep.FindConnectionByPID(42)
	for i := 0; i < edgeMaxDeliveryFailures; i++ { // each request makes the handler answer once
		r.post("/edge/rmc", map[string]any{"relay": "us-1", "pid": 42, "call": i, "proto": 1, "method": 1})
		time.Sleep(20 * time.Millisecond)
	}
	waitFor(t, "the orphaned session to be released", func() bool { return r.ep.FindConnectionByPID(42) == nil })
	if _, ok := edgeSessions.Load(uint32(42)); ok {
		t.Fatal("the session is still recorded")
	}
	_ = conn
}

func TestStatsAndTraceAreLoggedInTheDirectPathsFormat(t *testing.T) {
	r := newEdgeRig(t)
	r.open(t, "us-1", 42, 1000)
	r.post("/edge/stats", map[string]any{"relay": "us-1", "pid": 42, "ip": "1.2.3.4", "loss": "0%", "avg_rtt": "9ms", "prudp_rtt_ms": 20.5, "prudp_min_ms": 18.0, "samples": 4})
	r.post("/edge/stats", map[string]any{"relay": "us-1", "pid": 42, "ip": "1.2.3.4", "loss": "100%", "avg_rtt": "?", "samples": 0})
	r.post("/edge/trace", map[string]any{"relay": "us-1", "pid": 42, "ip": "1.2.3.4", "reason": "connect", "output": "traceroute to 1.2.3.4\n"})
	r.mu.Lock()
	all := strings.Join(r.logs, "")
	r.mu.Unlock()
	for _, want := range []string{
		"PlayerPing: PID=42 ip=1.2.3.4 loss=0% avgRTT=9ms via=edge:us-1",
		"PlayerRTT: PID=42 ip=1.2.3.4 via=edge:us-1 prudp=20.5ms min=18.0ms samples=4",
		"PlayerRTT: PID=42 ip=1.2.3.4 via=edge:us-1 prudp=? samples=0",
		"PlayerTraceroute: PID=42 ip=1.2.3.4 reason=connect via=edge:us-1\ntraceroute to 1.2.3.4",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("log lacks %q\nlog:\n%s", want, all)
		}
	}
}

func TestBadOpensAreRefused(t *testing.T) {
	r := newEdgeRig(t)
	for name, m := range map[string]map[string]any{
		"no pid":      {"relay": "us-1", "pid": 0, "ip": "1.2.3.4", "port": 1},
		"bad address": {"relay": "us-1", "pid": 5, "ip": "not-an-ip", "port": 1},
		"bad port":    {"relay": "us-1", "pid": 5, "ip": "1.2.3.4", "port": 70000},
	} {
		if c := r.post("/edge/open", m); c != http.StatusConflict {
			t.Errorf("%s: %d, want 409", name, c)
		}
	}
	if r.ep.FindConnectionByPID(5) != nil {
		t.Fatal("a refused open created a connection")
	}
}
