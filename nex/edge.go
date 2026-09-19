package nex

// Wii U Chat edge support (main side). A player's PRUDP session can be terminated on a regional relay
// (the "edge", relayd/wiiuchatedge in the Revivetendo bridge): the relay does the Kerberos handshake,
// acks and keepalives locally and forwards complete RMC calls here. To the protocol handlers such a
// player is an ordinary *nex.PRUDPConnection registered with the secure endpoint, except that
// everything the server sends to it goes to an OutHook (see third_party/nex-go-v2/edge_hooks.go)
// instead of a UDP socket, which covers the protocol library's own replies and notifications too.
//
// Off unless WUC_EDGE=1 or the file edge.enabled exists in the working directory. Listens on
// loopback only; the relay hub is the sole caller.
//
//	hub -> here   POST /edge/open   {relay,pid,ip,port}
//	              POST /edge/rmc    {relay,pid,call,proto,method,params}
//	              POST /edge/close  {relay,pid}
//	              POST /edge/stats  {relay,pid,ip,loss,avg_rtt,prudp_rtt_ms,prudp_min_ms,samples}
//	              POST /edge/trace  {relay,pid,ip,reason,output}
//	here -> hub   POST <hub>/wuc-edge/out {relay,pid,payload}   (an RMC message for the player)

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	nex "github.com/PretendoNetwork/nex-go/v2"
	"github.com/PretendoNetwork/nex-go/v2/constants"
	"github.com/PretendoNetwork/nex-go/v2/types"

	"github.com/PretendoNetwork/wiiu-chat/globals"
)

// edgeStreamID is the virtual port stream id given to a relay-terminated connection. Real consoles
// pick their own; nothing depends on the value, it only has to be a valid 4-bit id.
const edgeStreamID = 15

// A session whose outbound messages the hub cannot deliver this many times in a row is dropped: the
// relay no longer holds the player (hub restart, relay gone).
const edgeMaxDeliveryFailures = 3

type edgeSession struct {
	relay    string
	hub      string // where this session's outbound messages go, fixed when it starts
	conn     *nex.PRUDPConnection
	out      chan []byte // RMC messages for the player, sent in order by one goroutine
	done     chan struct{}
	stopped  chan struct{} // closed when the output goroutine has returned
	failures int
}

var (
	edgeSessions sync.Map // uint32 pid -> *edgeSession
	edgeHubURL   = "http://127.0.0.1:9401"

	edgeLogMu sync.RWMutex
	edgeLogf  = func(format string, a ...any) { fmt.Printf(format, a...) }
)

// elog logs through edgeLogf, which tests replace; safe to call from any goroutine.
func elog(format string, a ...any) {
	edgeLogMu.RLock()
	f := edgeLogf
	edgeLogMu.RUnlock()
	f(format, a...)
}

// setEdgeLogf replaces the logger and returns the previous one (tests).
func setEdgeLogf(f func(string, ...any)) func(string, ...any) {
	edgeLogMu.Lock()
	defer edgeLogMu.Unlock()
	old := edgeLogf
	edgeLogf = f
	return old
}

func edgeEnabled() bool {
	if os.Getenv("WUC_EDGE") == "1" {
		return true
	}
	_, err := os.Stat("edge.enabled")
	return err == nil
}

// startEdgeServer is called from StartSecureServer just before it listens.
func startEdgeServer() {
	go logDirectRTT() // baseline for comparing the edge with the direct path: always on
	if !edgeEnabled() {
		return
	}
	if v := os.Getenv("WUC_EDGE_HUB"); v != "" {
		edgeHubURL = v
	}
	addr := os.Getenv("WUC_EDGE_ADDR")
	if addr == "" {
		addr = "127.0.0.1:9452"
	}
	elog("Edge: accepting relay-terminated sessions on %s (hub %s)\n", addr, edgeHubURL)
	go func() {
		if err := http.ListenAndServe(addr, edgeMux()); err != nil {
			elog("Edge: listener stopped: %v\n", err)
		}
	}()
}

func edgeMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/edge/open", edgeHandler(handleEdgeOpen))
	mux.HandleFunc("/edge/rmc", edgeHandler(handleEdgeRMC))
	mux.HandleFunc("/edge/alive", edgeHandler(func(*edgeMsg) error { return nil })) // the relay runs the heartbeats
	mux.HandleFunc("/edge/close", edgeHandler(handleEdgeClose))
	mux.HandleFunc("/edge/stats", edgeHandler(handleEdgeStats))
	mux.HandleFunc("/edge/trace", edgeHandler(handleEdgeTrace))
	return mux
}

type edgeMsg struct {
	Relay  string `json:"relay"`
	PID    uint32 `json:"pid"`
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Call   uint32 `json:"call"`
	Proto  uint16 `json:"proto"`
	Method uint32 `json:"method"`
	Params []byte `json:"params"`

	// connectivity measurements taken on the relay
	Loss       string  `json:"loss"`
	AvgRTT     string  `json:"avg_rtt"`
	PRUDPRTTMs float64 `json:"prudp_rtt_ms"`
	PRUDPMinMs float64 `json:"prudp_min_ms"`
	Samples    int     `json:"samples"`
	Reason     string  `json:"reason"`
	Output     string  `json:"output"`
}

func edgeHandler(fn func(m *edgeMsg) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var m edgeMsg
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20)).Decode(&m); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		defer func() {
			if rec := recover(); rec != nil {
				elog("Edge: %s panicked: %v\n", r.URL.Path, rec)
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
		}()
		if err := fn(&m); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// handleEdgeOpen registers a session whose Kerberos handshake the relay already verified.
func handleEdgeOpen(m *edgeMsg) error {
	ip := net.ParseIP(m.IP)
	if m.PID == 0 || ip == nil || m.Port <= 0 || m.Port > 65535 {
		return fmt.Errorf("bad open")
	}
	conn := globals.SecureEndpoint.NewVirtualConnection(&net.UDPAddr{IP: ip, Port: m.Port}, types.NewPID(uint64(m.PID)), constants.StreamTypeRVSecure, edgeStreamID)
	s := &edgeSession{relay: m.Relay, hub: edgeHubURL, conn: conn, out: make(chan []byte, 256), done: make(chan struct{}), stopped: make(chan struct{})}
	conn.OutHook = func(p nex.PRUDPPacketInterface) { s.deliver(p) }

	// A reconnect replaces the previous session for this PID (real or edge), like a second connection.
	if old, ok := edgeSessions.Swap(m.PID, s); ok {
		old.(*edgeSession).end()
	}
	go s.pump(m.PID)
	elog("Connect: PID=%d (edge %s, %s:%d)\n", m.PID, m.Relay, m.IP, m.Port)
	return nil
}

func handleEdgeRMC(m *edgeMsg) error {
	v, ok := edgeSessions.Load(m.PID)
	if !ok {
		return fmt.Errorf("no edge session for pid %d", m.PID)
	}
	s := v.(*edgeSession)
	if s.relay != m.Relay {
		return fmt.Errorf("pid %d belongs to another relay", m.PID)
	}
	msg := nex.NewRMCRequest(globals.SecureEndpoint)
	msg.ProtocolID = m.Proto
	msg.CallID = m.Call
	msg.MethodID = m.Method
	msg.Parameters = m.Params
	pkt, err := nex.NewPRUDPPacketV1(globals.SecureServer, s.conn, nil)
	if err != nil {
		return err
	}
	pkt.SetType(constants.DataPacket)
	pkt.SetRMCMessage(msg)
	// The protocol handlers may take a while and the relay is waiting for our answer: hand the request
	// over and return, exactly as a socket read would.
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				elog("Edge: PID=%d proto=%#x method=%#x panicked: %v\n", m.PID, m.Proto, m.Method, rec)
			}
		}()
		globals.SecureEndpoint.Emit("data", pkt)
	}()
	return nil
}

func handleEdgeClose(m *edgeMsg) error {
	v, ok := edgeSessions.Load(m.PID)
	if !ok {
		return nil
	}
	s := v.(*edgeSession)
	if s.relay != m.Relay {
		return fmt.Errorf("pid %d belongs to another relay", m.PID)
	}
	if !edgeSessions.CompareAndDelete(m.PID, s) {
		return nil // a newer session already replaced it
	}
	s.end()
	elog("Disconnect: PID=%d (edge %s)\n", m.PID, m.Relay)
	return nil
}

// handleEdgeStats logs what a relay measured toward one of its players, in the same lines as the
// direct path (PlayerRTT via=direct), so one grep compares both.
func handleEdgeStats(m *edgeMsg) error {
	v, ok := edgeSessions.Load(m.PID)
	if !ok || v.(*edgeSession).relay != m.Relay {
		return fmt.Errorf("no edge session for pid %d on relay %s", m.PID, m.Relay)
	}
	via := "edge:" + m.Relay
	elog("PlayerPing: PID=%d ip=%s loss=%s avgRTT=%s via=%s\n", m.PID, m.IP, m.Loss, m.AvgRTT, via)
	if m.Samples == 0 {
		elog("PlayerRTT: PID=%d ip=%s via=%s prudp=? samples=0\n", m.PID, m.IP, via)
	} else {
		elog("PlayerRTT: PID=%d ip=%s via=%s prudp=%.1fms min=%.1fms samples=%d\n", m.PID, m.IP, via, m.PRUDPRTTMs, m.PRUDPMinMs, m.Samples)
	}
	return nil
}

func handleEdgeTrace(m *edgeMsg) error {
	v, ok := edgeSessions.Load(m.PID)
	if !ok || v.(*edgeSession).relay != m.Relay {
		return fmt.Errorf("no edge session for pid %d on relay %s", m.PID, m.Relay)
	}
	elog("PlayerTraceroute: PID=%d ip=%s reason=%s via=edge:%s\n%s", m.PID, m.IP, m.Reason, m.Relay, m.Output)
	return nil
}

// end stops the session's output and unregisters its connection (firing the endpoint's
// connection-ended handlers, which is how the chat logic cleans up a player that left).
func (s *edgeSession) end() {
	select {
	case <-s.done:
		return
	default:
		close(s.done)
	}
	globals.SecureEndpoint.RemoveVirtualConnection(s.conn)
}

// deliver receives what the server would have sent to the player. Only data packets carry an RMC
// message; anything else means nothing to the edge.
func (s *edgeSession) deliver(p nex.PRUDPPacketInterface) {
	if p.Type() != constants.DataPacket {
		return
	}
	payload := append([]byte(nil), p.Payload()...)
	select {
	case s.out <- payload:
	default:
		elog("Edge: PID=%d outbound queue full, dropping a message\n", uint64(s.conn.PID()))
	}
}

// pump sends the session's messages to the hub in order, one at a time.
func (s *edgeSession) pump(pid uint32) {
	defer close(s.stopped)
	client := &http.Client{Timeout: 5 * time.Second}
	for {
		select {
		case <-s.done:
			return
		case payload := <-s.out:
			body, _ := json.Marshal(struct {
				Relay   string `json:"relay"`
				PID     uint32 `json:"pid"`
				Payload []byte `json:"payload"`
			}{s.relay, pid, payload})
			resp, err := client.Post(s.hub+"/wuc-edge/out", "application/json", bytes.NewReader(body))
			if err != nil {
				elog("Edge: PID=%d could not reach the hub: %v\n", pid, err)
				continue
			}
			resp.Body.Close()
			switch {
			case resp.StatusCode == http.StatusNotFound:
				// The hub does not know a relay holding this player (it restarted, or the relay is
				// gone). After a few in a row the session is dead: drop it.
				s.failures++
				if s.failures >= edgeMaxDeliveryFailures {
					if edgeSessions.CompareAndDelete(pid, s) {
						s.end()
						elog("Edge: PID=%d released: the hub no longer knows a relay holding it (%s)\n", pid, s.relay)
					}
					return
				}
			case resp.StatusCode >= 300:
				elog("Edge: PID=%d hub refused a message: %s\n", pid, resp.Status)
			default:
				s.failures = 0
			}
		}
	}
}

// logDirectRTT logs the acknowledgement round trip of every direct (non-relay) connection every 30
// seconds, in the same format the edge's stats use, so the two paths can be compared with one grep.
func logDirectRTT() {
	for range time.Tick(30 * time.Second) {
		if globals.SecureEndpoint == nil {
			continue
		}
		globals.SecureEndpoint.Connections.Each(func(_ string, c *nex.PRUDPConnection) bool {
			pid := uint64(c.PID())
			if c.OutHook != nil || pid == 0 || c.Socket == nil || c.Socket.Address == nil {
				return true
			}
			sm, min, n := c.RTT().Smoothed()
			host, _, err := net.SplitHostPort(c.Socket.Address.String())
			if err != nil {
				host = c.Socket.Address.String()
			}
			if n == 0 {
				elog("PlayerRTT: PID=%d ip=%s via=direct prudp=? samples=0\n", pid, host)
			} else {
				elog("PlayerRTT: PID=%d ip=%s via=direct prudp=%.1fms min=%.1fms samples=%d\n", pid, host,
					float64(sm)/float64(time.Millisecond), float64(min)/float64(time.Millisecond), n)
			}
			return true
		})
	}
}
