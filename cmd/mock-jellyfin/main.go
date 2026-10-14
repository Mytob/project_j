package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type publicInfo struct {
	ServerName  string `json:"ServerName"`
	ProductName string `json:"ProductName"`
	Version     string `json:"Version"`
}

func main() {
	mux := http.NewServeMux()
	var publicInfoRequests atomic.Int64
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/System/Info/Public", func(w http.ResponseWriter, _ *http.Request) {
		publicInfoRequests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(publicInfo{
			ServerName:  "local-test-jellyfin",
			ProductName: "Jellyfin",
			Version:     "mock",
		})
	})
	mux.HandleFunc("/__requests", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(fmt.Sprintf("%d\n", publicInfoRequests.Load())))
	})
	mux.HandleFunc("/__stream", func(w http.ResponseWriter, r *http.Request) {
		size := 2 << 20
		if raw := r.URL.Query().Get("bytes"); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil || parsed < 0 || parsed > 8<<20 {
				http.Error(w, "invalid stream size", http.StatusBadRequest)
				return
			}
			size = parsed
		}
		start, end, partial := 0, size-1, false
		if value := r.Header.Get("Range"); value != "" {
			var err error
			start, end, err = parseRange(value, size)
			if err != nil {
				w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", size))
				http.Error(w, "invalid range", http.StatusRequestedRangeNotSatisfiable)
				return
			}
			partial = true
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, size))
		}
		length := end - start + 1
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(length))
		w.Header().Set("Accept-Ranges", "bytes")
		if partial {
			w.WriteHeader(http.StatusPartialContent)
		}
		if size == 0 {
			w.WriteHeader(http.StatusOK)
			return
		}
		flusher, _ := w.(http.Flusher)
		chunk := make([]byte, 16<<10)
		written := 0
		for written < length {
			count := min(len(chunk), length-written)
			for i := 0; i < count; i++ {
				chunk[i] = byte((start + written + i) % 251)
			}
			n, err := w.Write(chunk[:count])
			written += n
			if err != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
			if r.URL.Query().Get("slow") == "1" {
				time.Sleep(40 * time.Millisecond)
			}
		}
	})
	mux.HandleFunc("/__ws", websocketEcho)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"service": "mock-jellyfin",
			"path":    r.URL.Path,
		})
	})

	server := &http.Server{
		Addr:              ":8096",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("mock Jellyfin listening on %s", server.Addr)
	log.Fatal(server.ListenAndServe())
}

func parseRange(value string, size int) (int, int, error) {
	if !strings.HasPrefix(value, "bytes=") || strings.Contains(value, ",") || size <= 0 {
		return 0, 0, fmt.Errorf("unsupported byte range")
	}
	parts := strings.Split(strings.TrimPrefix(value, "bytes="), "-")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return 0, 0, fmt.Errorf("unsupported byte range")
	}
	start, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, err
	}
	end, err := strconv.Atoi(parts[1])
	if err != nil || start < 0 || end < start || end >= size {
		return 0, 0, fmt.Errorf("invalid byte range")
	}
	return start, end, nil
}

func websocketEcho(w http.ResponseWriter, r *http.Request) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") || !strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") || r.Header.Get("Sec-WebSocket-Version") != "13" {
		http.Error(w, "websocket upgrade required", http.StatusBadRequest)
		return
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		http.Error(w, "websocket key required", http.StatusBadRequest)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "websocket unavailable", http.StatusInternalServerError)
		return
	}
	conn, rw, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	accept := websocketAccept(key)
	if _, err := fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept); err != nil {
		return
	}
	if err := rw.Flush(); err != nil {
		return
	}
	for {
		opcode, payload, err := readWebSocketFrame(rw.Reader)
		if err != nil {
			return
		}
		if opcode == 8 {
			_, _ = rw.Writer.Write([]byte{0x88, 0x00})
			_ = rw.Flush()
			return
		}
		if opcode != 1 {
			continue
		}
		if err := writeWebSocketFrame(rw.Writer, 1, payload); err != nil {
			return
		}
		if err := rw.Flush(); err != nil {
			return
		}
	}
}

func websocketAccept(key string) string {
	hash := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(hash[:])
}

func readWebSocketFrame(reader *bufio.Reader) (byte, []byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return 0, nil, err
	}
	opcode := header[0] & 0x0f
	length := uint64(header[1] & 0x7f)
	if length == 126 {
		var extended [2]byte
		if _, err := io.ReadFull(reader, extended[:]); err != nil {
			return 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(extended[:]))
	} else if length == 127 {
		var extended [8]byte
		if _, err := io.ReadFull(reader, extended[:]); err != nil {
			return 0, nil, err
		}
		length = binary.BigEndian.Uint64(extended[:])
	}
	if length > 1<<20 {
		return 0, nil, fmt.Errorf("websocket frame exceeds test limit")
	}
	var mask [4]byte
	masked := header[1]&0x80 != 0
	if masked {
		if _, err := io.ReadFull(reader, mask[:]); err != nil {
			return 0, nil, err
		}
	}
	payload := make([]byte, int(length))
	if _, err := io.ReadFull(reader, payload); err != nil {
		return 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return opcode, payload, nil
}

func writeWebSocketFrame(writer *bufio.Writer, opcode byte, payload []byte) error {
	header := []byte{0x80 | opcode}
	switch {
	case len(payload) < 126:
		header = append(header, byte(len(payload)))
	case len(payload) <= 65535:
		header = append(header, 126, 0, 0)
		binary.BigEndian.PutUint16(header[len(header)-2:], uint16(len(payload)))
	default:
		header = append(header, 127, 0, 0, 0, 0, 0, 0, 0, 0)
		binary.BigEndian.PutUint64(header[len(header)-8:], uint64(len(payload)))
	}
	if _, err := writer.Write(header); err != nil {
		return err
	}
	_, err := writer.Write(payload)
	return err
}
