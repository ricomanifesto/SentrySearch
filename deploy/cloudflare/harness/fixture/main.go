// Command fixture stands in for the service images in the local harness's
// self-test, so the Worker scripts can run end to end before (or without) the
// real AMD64 images. It is installed at the paths the Durable Objects start
// (/usr/local/bin/tini and /app/cfinit) and picks its role from the command it
// is given. It never ships in a service image.
//
//	runtime: TLS listener on :8443 that requires the fixture bearer token.
//	worker:  posts v1 readiness receipts to http://evidence.internal and checks
//	         the runtime through ws://runtime.internal with verified TLS.
//	api:     HTTP on :8001; /health, and /probe reports whether the runtime
//	         relay or an outside address is reachable (both must not be).
//	job:     "proof" ignores SIGTERM and runs until destroyed (the deadline
//	         case); other jobs exit 0 after FIXTURE_JOB_SECONDS.
package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

func main() {
	joined := strings.Join(os.Args, " ")
	switch {
	case strings.Contains(joined, "/app/sentryruntime"):
		runtimeRole()
	case strings.Contains(joined, "dev.run_runtime_worker"):
		workerRole()
	case strings.Contains(joined, "/app/run_api.py"):
		apiRole()
	case strings.Contains(joined, "release_tools"):
		jobRole()
	default:
		fmt.Fprintln(os.Stderr, "fixture: unknown role")
		os.Exit(64)
	}
}

func env(name string) string { return os.Getenv(name) }

func runtimeRole() {
	certificate, err := tls.X509KeyPair([]byte(env("FIXTURE_TLS_CERT")), []byte(env("FIXTURE_TLS_KEY")))
	if err != nil {
		fmt.Fprintln(os.Stderr, "fixture runtime: bad certificate")
		os.Exit(78)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+env("FIXTURE_TOKEN") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Fprintln(w, "ok")
	})
	server := &http.Server{Addr: ":8443", Handler: mux, TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}}
	stopOnTerm(func() { server.Close() })
	fmt.Println("fixture runtime: listening on 8443")
	if err := server.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		os.Exit(1)
	}
}

func apiRole() {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "ok") })
	mux.HandleFunc("/probe", func(w http.ResponseWriter, _ *http.Request) {
		result := map[string]string{"runtime_relay": "unreachable", "outside": "unreachable"}
		if _, err := tunnel("runtime.internal"); err == nil {
			result["runtime_relay"] = "REACHED"
		}
		if target := env("FIXTURE_OUTSIDE_TARGET"); target != "" {
			if connection, err := net.DialTimeout("tcp", target, 3*time.Second); err == nil {
				// The sidecar may accept locally; only an answer from the target counts.
				connection.SetDeadline(time.Now().Add(3 * time.Second))
				fmt.Fprintf(connection, "GET / HTTP/1.0\r\n\r\n")
				if line, err := bufio.NewReader(connection).ReadString('\n'); err == nil && strings.HasPrefix(line, "HTTP/") {
					result["outside"] = "REACHED"
				}
				connection.Close()
			}
		}
		json.NewEncoder(w).Encode(result)
	})
	server := &http.Server{Addr: ":8001", Handler: mux}
	stopOnTerm(func() { server.Close() })
	server.ListenAndServe()
}

func jobRole() {
	if os.Args[len(os.Args)-1] == "proof" {
		signal.Ignore(syscall.SIGTERM)
		time.Sleep(time.Hour)
		return
	}
	seconds, _ := strconv.Atoi(env("FIXTURE_JOB_SECONDS"))
	time.Sleep(time.Duration(seconds) * time.Second)
}

func stopOnTerm(stop func()) {
	terms := make(chan os.Signal, 1)
	signal.Notify(terms, syscall.SIGTERM)
	go func() {
		<-terms
		stop()
		os.Exit(0)
	}()
}

// workerRole posts receipts and checks the runtime every two seconds.
func workerRole() {
	bootID := make([]byte, 16)
	rand.Read(bootID)
	started := time.Now()
	var mutex sync.Mutex
	sequence := 0
	send := func(alive, ready, draining bool, phase string, errorCode any) {
		mutex.Lock()
		sequence++
		receipt := map[string]any{
			"kind": "sentry.worker-readiness.v1", "release_id": env("SENTRYSEARCH_RELEASE_ID"),
			"boot_id": hex.EncodeToString(bootID), "sequence": sequence,
			"observed_at":    time.Now().UTC().Format("2006-01-02T15:04:05.000000Z"),
			"uptime_seconds": float64(time.Since(started).Microseconds()) / 1e6,
			"alive":          alive, "ready": ready, "draining": draining, "phase": phase,
			"phase_elapsed_seconds": 0.0, "phase_budget_seconds": 0.0, "error_code": errorCode,
		}
		mutex.Unlock()
		body, _ := json.Marshal(receipt)
		client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}}
		response, err := client.Post(env("SENTRYSEARCH_RECEIPT_URL"), "application/json", bytes.NewReader(body))
		if err != nil {
			fmt.Printf("fixture worker: receipt %d not delivered: %v\n", receipt["sequence"], err)
			return
		}
		response.Body.Close()
		fmt.Printf("fixture worker: receipt %d draining=%v status %d\n", receipt["sequence"], draining, response.StatusCode)
	}
	terms := make(chan os.Signal, 1)
	signal.Notify(terms, syscall.SIGTERM)
	for {
		status, err := tunnel("runtime.internal")
		if err == nil && status == http.StatusOK {
			send(true, true, false, "idle", nil)
		} else {
			send(true, false, false, "idle", "runtime_unavailable")
		}
		select {
		case <-terms:
			// As the worker does: "stopped" while alive, then the terminal receipt.
			send(true, false, true, "stopped", nil)
			send(false, false, true, "stopped", nil)
			os.Exit(0)
		case <-time.After(2 * time.Second):
		}
	}
}

// tunnel opens ws://host/v1/tunnel and makes one verified HTTPS request to the
// runtime through it, returning the HTTP status.
func tunnel(host string) (int, error) {
	connection, err := net.DialTimeout("tcp", host+":80", 3*time.Second)
	if err != nil {
		return 0, err
	}
	defer connection.Close()
	connection.SetDeadline(time.Now().Add(10 * time.Second))
	keyBytes := make([]byte, 16)
	rand.Read(keyBytes)
	key := base64.StdEncoding.EncodeToString(keyBytes)
	fmt.Fprintf(connection, "GET /v1/tunnel HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n", host, key)
	reader := bufio.NewReader(connection)
	response, err := http.ReadResponse(reader, nil)
	if err != nil || response.StatusCode != http.StatusSwitchingProtocols {
		return 0, errors.New("upgrade refused")
	}
	digest := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	if response.Header.Get("Sec-Websocket-Accept") != base64.StdEncoding.EncodeToString(digest[:]) {
		return 0, errors.New("bad accept")
	}
	stream := &wsConn{Conn: connection, reader: reader}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(env("FIXTURE_RUNTIME_CA"))) {
		return 0, errors.New("no runtime CA")
	}
	client := tls.Client(stream, &tls.Config{RootCAs: roots, ServerName: "runtime.test", MinVersion: tls.VersionTLS12})
	if err := client.Handshake(); err != nil {
		return 0, err
	}
	fmt.Fprintf(client, "GET /v1/health HTTP/1.1\r\nHost: runtime.test\r\nAuthorization: Bearer %s\r\nConnection: close\r\n\r\n", env("FIXTURE_TOKEN"))
	answer, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		return 0, err
	}
	answer.Body.Close()
	return answer.StatusCode, nil
}

// wsConn is a net.Conn over binary WebSocket frames (client side, masked).
type wsConn struct {
	net.Conn
	reader  *bufio.Reader
	pending []byte
}

func (c *wsConn) Write(data []byte) (int, error) {
	header := []byte{0x82}
	switch length := len(data); {
	case length < 126:
		header = append(header, byte(0x80|length))
	case length <= 0xffff:
		header = append(header, 0x80|126, byte(length>>8), byte(length))
	default:
		header = append(header, 0x80|127)
		header = binary.BigEndian.AppendUint64(header, uint64(length))
	}
	mask := make([]byte, 4)
	rand.Read(mask)
	frame := append(header, mask...)
	for i, b := range data {
		frame = append(frame, b^mask[i%4])
	}
	if _, err := c.Conn.Write(frame); err != nil {
		return 0, err
	}
	return len(data), nil
}

func (c *wsConn) Read(buffer []byte) (int, error) {
	for len(c.pending) == 0 {
		head := make([]byte, 2)
		if _, err := io.ReadFull(c.reader, head); err != nil {
			return 0, err
		}
		length := uint64(head[1] & 0x7f)
		if length == 126 {
			extended := make([]byte, 2)
			io.ReadFull(c.reader, extended)
			length = uint64(binary.BigEndian.Uint16(extended))
		} else if length == 127 {
			extended := make([]byte, 8)
			io.ReadFull(c.reader, extended)
			length = binary.BigEndian.Uint64(extended)
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(c.reader, payload); err != nil {
			return 0, err
		}
		switch head[0] & 0x0f {
		case 0x8:
			return 0, io.EOF
		case 0x2, 0x0:
			c.pending = payload
		}
	}
	n := copy(buffer, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}
