package server

import (
	"Bee/internal/hub"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// uploadBufferPool is a sync.Pool that recycles byte slices of size 256KB
// we allocate 256KB first time and reuse it when the ptr is returned to the pool
var uploadBufferPool = sync.Pool{
	New: func() interface{} {
		buffer := make([]byte, 256*1024) // 256KB buffer optimized for gigabit LAN
		return &buffer
	},
}

type Server struct {
	Hub            *hub.Hub
	Port           string
	Pin            string
	FrontendFS     http.FileSystem // Optional embedded frontend filesystem
	activeUploads  sync.WaitGroup  // Security: Track uploads for graceful shutdown (CWE-404)
	shutdownCtx    context.Context
	shutdownCancel context.CancelFunc
}

func NewServer(port, pin string) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		Hub:            hub.NewHub(),
		Port:           port,
		Pin:            pin,
		shutdownCtx:    ctx,
		shutdownCancel: cancel,
	}
}

const (
	// WebSocket timeout constants
	writeWait  = 10 * time.Second // Time allowed to write a message to the peer
	pongWait   = 60 * time.Second // Time allowed to read the next pong message from the peer
	pingPeriod = 30 * time.Second // Send pings to peer with this period (must be less than pongWait)
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all for LAN
	},
}

func (s *Server) Start(openBrowser bool) {
	// Ensure uploads directory exists
	if _, err := os.Stat("uploads"); os.IsNotExist(err) {
		os.Mkdir("uploads", 0755)
	}

	go s.Hub.Run()

	// Upload Handler
	http.HandleFunc("/upload", s.handleUpload)
	// Serve Uploaded Files with security headers
	http.HandleFunc("/upload/", s.handleFileDownload)

	// List Files Handler
	http.HandleFunc("/files", s.handleListFiles)
	// Delete File Handler - Security: File deletion capability (CWE-459)
	http.HandleFunc("/delete/", s.handleDeleteFile)

	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		// Validate PIN
		pin := r.URL.Query().Get("pin")
		name := r.URL.Query().Get("name")
		device := r.URL.Query().Get("device")

		if pin != s.Pin {
			log.Printf("AUTH FAILED: IP=%s Name=%s PIN=%s (Expected: %s)", r.RemoteAddr, name, pin, s.Pin)
			http.Error(w, "Invalid PIN", http.StatusUnauthorized)
			return
		}
		if name == "" {
			http.Error(w, "Name Required", http.StatusBadRequest)
			return
		}

		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Println(err)
			return
		}

		// Extract IP address (strip port)
		ip := extractIP(r.RemoteAddr)

		client := &hub.Client{Hub: s.Hub, Conn: conn, Send: make(chan []byte, 256), Name: name, Device: device, IP: ip}
		s.Hub.Register <- client

		// Send current file list to the new client specifically
		files, _ := s.listFiles()
		msg, _ := json.Marshal(map[string]interface{}{
			"type": "files",
			"data": files,
		})
		client.Send <- msg

		// Configure ping/pong handler
		conn.SetReadDeadline(time.Now().Add(pongWait))
		conn.SetPongHandler(func(string) error {
			conn.SetReadDeadline(time.Now().Add(pongWait))
			return nil
		})

		// Ticker for sending periodic pings
		ticker := time.NewTicker(pingPeriod)

		// Handle incoming messages
		go func() {
			// Security: Proper resource cleanup to prevent leaks (CWE-404)
			defer func() {
				ticker.Stop()
				s.Hub.Unregister <- client
				conn.Close()
				log.Printf("[CLEANUP] WebSocket connection closed: %s", client.Name)
			}()
			for {
				_, _, err := conn.ReadMessage()
				if err != nil {
					if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
						log.Printf("WebSocket error: %v", err)
					}
					break
				}
				// For now, just ignore echo or handle specific logic
			}
		}()

		// Handle outgoing messages and pings
		go func() {
			defer func() {
				ticker.Stop()
				conn.Close()
			}()
			for {
				select {
				case message, ok := <-client.Send:
					conn.SetWriteDeadline(time.Now().Add(writeWait))
					if !ok {
						// Hub closed the channel
						conn.WriteMessage(websocket.CloseMessage, []byte{})
						return
					}
					if err := conn.WriteMessage(websocket.TextMessage, message); err != nil {
						return
					}
				case <-ticker.C:
					conn.SetWriteDeadline(time.Now().Add(writeWait))
					if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
						return
					}
				}
			}
		}()
	})

	// Serve Frontend
	// Use embedded files if provided, otherwise serve from disk (development mode)
	if s.FrontendFS != nil {
		// Production: use embedded files
		http.Handle("/", http.FileServer(s.FrontendFS))
	} else {
		// Development: serve from disk
		http.Handle("/", http.FileServer(http.Dir("./frontend/dist")))
	}

	ip := getLocalIP()

	fmt.Println("\n=================================================")
	fmt.Println("   Bee: LAN File Sharing")
	fmt.Println("=================================================")
	fmt.Printf(" Server running at: http://%s:%s\n", ip, s.Port)
	fmt.Printf(" Access PIN:        %s\n", s.Pin)
	fmt.Println("-------------------------------------------------")
	fmt.Println(" Share this URL and PIN with others on your Wi-Fi")
	fmt.Println("=================================================")

	// Security: Browser auto-open configuration (Low severity fix)
	if openBrowser {
		openBrowserFunc(fmt.Sprintf("http://localhost:%s", s.Port))
	}

	// Handle Graceful Shutdown
	stop := make(chan os.Signal, 1)
	// SIGINT for Ctrl+C, SIGTERM for kill command
	// On Windows, syscall.SIGTERM is not supported for os.Notify, so we rely on os.Interrupt (Ctrl+C)
	// or we can read from Stdin for "Enter" to quit.
	// Let's support both.
	signal.Notify(stop, os.Interrupt)

	go func() {
		fmt.Println(" Server is running. Press CTRL+C to stop.")
		if err := http.ListenAndServe(":"+s.Port, nil); err != nil {
			log.Fatal(err)
		}
	}()

	<-stop
	fmt.Println("\nShutting down server...")
	s.shutdownCancel()
	
	// Security: Graceful shutdown - wait for active uploads (CWE-404)
	done := make(chan struct{})
	go func() {
		s.activeUploads.Wait()
		close(done)
	}()
	
	select {
	case <-done:
		log.Println("[SHUTDOWN] All uploads completed gracefully")
	case <-time.After(30 * time.Second):
		log.Println("[SHUTDOWN] Timeout reached, forcing exit")
	}
	
	os.Exit(0)
}

func getLocalIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "localhost"
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

func extractIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr // Return as-is if parsing fails
	}
	return host
}

// Security: Add security headers middleware
func (s *Server) setSecurityHeaders(w http.ResponseWriter) {
	// Security: CSP to prevent XSS (CWE-1021)
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws: wss:")
	// Security: Additional security headers (CWE-693)
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	s.setSecurityHeaders(w)
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method == "OPTIONS" {
		return
	}
	
	// Security: Track active uploads for graceful shutdown (CWE-404)
	s.activeUploads.Add(1)
	defer s.activeUploads.Done()

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Use MultipartReader for true streaming (no full-parse in RAM/Temp)
	reader, err := r.MultipartReader()
	if err != nil {
		http.Error(w, "Invalid multipart request", http.StatusBadRequest)
		return
	}

	// Ensure uploads dir exists
	if _, err := os.Stat("uploads"); os.IsNotExist(err) {
		os.Mkdir("uploads", 0755)
	}

	// Iterate over parts
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("Error reading part: %v", err)
			http.Error(w, "Upload error", http.StatusInternalServerError)
			return
		}

		// Only process the file field
		if part.FormName() == "file" {
			filename := filepath.Base(part.FileName())
			if filename == "" {
				continue
			}

			savePath := filepath.Join("uploads", filename)
			// Ensure unique name with crypto-random prefix
			if _, err := os.Stat(savePath); err == nil {
				// Security: Use crypto-random prefix instead of predictable timestamp (CWE-330)
				randomBytes := make([]byte, 8)
				rand.Read(randomBytes)
				filename = fmt.Sprintf("%x_%s", randomBytes, filename)
				savePath = filepath.Join("uploads", filename)
			}

			dst, err := os.Create(savePath)
			if err != nil {
				// Security: Generic error message to prevent info disclosure (CWE-209)
				log.Printf("[ERROR] File creation failed: %v", err)
				http.Error(w, "Upload failed", http.StatusInternalServerError)
				return
			}

			// Stream directly from Network -> Disk with optimized pooled buffer
			// 256KB buffer over default 32KB
			bufferPtr := uploadBufferPool.Get().(*[]byte)
			defer uploadBufferPool.Put(bufferPtr)
			clear(*bufferPtr) // Clear the buffer before using it

			size, err := io.CopyBuffer(dst, part, *bufferPtr)
			dst.Close()

			if err != nil {
				// Security: Generic error message (CWE-209)
				log.Printf("[ERROR] File copy failed: %v", err)
				http.Error(w, "Upload failed", http.StatusInternalServerError)
				return
			}

			// Security: Audit log for file operations (CWE-778)
			log.Printf("[AUDIT] File uploaded: %s | Size: %d bytes | IP: %s", filename, size, extractIP(r.RemoteAddr))
		}
	}

	// Broadcast Update
	s.broadcastFileList()

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Upload successful"))
}

func (s *Server) handleListFiles(w http.ResponseWriter, r *http.Request) {
	s.setSecurityHeaders(w)
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	files, err := s.listFiles()
	if err != nil {
		// Security: Generic error message (CWE-209)
		log.Printf("[ERROR] File listing failed: %v", err)
		http.Error(w, "Failed to list files", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(files)
}

func (s *Server) listFiles() ([]map[string]interface{}, error) {
	if _, err := os.Stat("uploads"); os.IsNotExist(err) {
		os.Mkdir("uploads", 0755)
		return []map[string]interface{}{}, nil
	}

	entries, err := os.ReadDir("uploads")
	if err != nil {
		return nil, err
	}

	fileList := []map[string]interface{}{}
	for _, e := range entries {
		if !e.IsDir() {
			info, _ := e.Info()
			fileList = append(fileList, map[string]interface{}{
				"name": e.Name(),
				"size": info.Size(),
				"time": info.ModTime(),
			})
		}
	}
	return fileList, nil
}

func (s *Server) broadcastFileList() {
	files, _ := s.listFiles()
	msg, _ := json.Marshal(map[string]interface{}{
		"type": "files",
		"data": files,
	})
	s.Hub.Broadcast <- msg // Hub handles unsafe send now? No, we fixed it.
	// Actually, ensure we use the safe send if we can access Hub methods,
	// or just send to Broadcast channel which Hub.Run consumes.
	// The previous fix ensures Hub.Run uses `sendToAll`.
}

// Security: File download handler with audit logging (CWE-778)
func (s *Server) handleFileDownload(w http.ResponseWriter, r *http.Request) {
	s.setSecurityHeaders(w)
	filename := strings.TrimPrefix(r.URL.Path, "/upload/")
	filePath := filepath.Join("uploads", filepath.Base(filename))
	
	// Security: Audit log for downloads (CWE-778)
	log.Printf("[AUDIT] File download: %s | IP: %s", filename, extractIP(r.RemoteAddr))
	
	http.ServeFile(w, r, filePath)
}

// Security: File deletion handler (CWE-459)
func (s *Server) handleDeleteFile(w http.ResponseWriter, r *http.Request) {
	s.setSecurityHeaders(w)
	w.Header().Set("Access-Control-Allow-Origin", "*")
	
	if r.Method != "DELETE" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	filename := strings.TrimPrefix(r.URL.Path, "/delete/")
	filePath := filepath.Join("uploads", filepath.Base(filename))
	
	// Security: Audit log before deletion (CWE-778)
	log.Printf("[AUDIT] File deletion requested: %s | IP: %s", filename, extractIP(r.RemoteAddr))
	
	if err := os.Remove(filePath); err != nil {
		log.Printf("[ERROR] File deletion failed: %v", err)
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	
	log.Printf("[AUDIT] File deleted: %s", filename)
	s.broadcastFileList()
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("File deleted"))
}

func openBrowserFunc(url string) {
	var err error
	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("unsupported platform")
	}
	if err != nil {
		log.Printf("Failed to open browser: %v", err)
	}
}
