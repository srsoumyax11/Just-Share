package main

import (
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"time"

	"Bee/internal/server"
)

// Security: Version tracking for update checks (CWE-1104)
var version = "dev"

func main() {
	fmt.Printf("Bee version: %s\n", version)
	port := flag.String("port", "1111", "Port to run the server on")
	pin := flag.String("pin", "", "6-digit Access PIN (optional, generated if empty)")
	// Security: Browser auto-open flag (Low severity fix)
	openBrowser := flag.Bool("open-browser", false, "Automatically open browser on startup")
	flag.Parse()

	if *pin == "" {
		// rand.Seed(time.Now().UnixNano())
		// *pin = fmt.Sprintf("%06d", rand.Intn(1000000))
		*pin = "111111" // Hardcoded for now
	}

	// Security: Check for updates (CWE-1104) - non-blocking
	go checkForUpdates()

	srv := server.NewServer(*port, *pin)
	// Set embedded frontend filesystem
	srv.FrontendFS = http.FS(GetFrontendFS())
	srv.Start(*openBrowser)
}

//go:embed frontend/dist
var frontendFS embed.FS

// GetFrontendFS returns the embedded frontend filesystem
func GetFrontendFS() fs.FS {
	frontendSubFS, err := fs.Sub(frontendFS, "frontend/dist")
	if err != nil {
		log.Fatal("Failed to load embedded frontend:", err)
	}
	return frontendSubFS
}

// Security: Update check mechanism (CWE-1104)
func checkForUpdates() {
	if version == "dev" {
		return // Skip check in development
	}
	
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://api.github.com/repos/srsoumyax11/bee/releases/latest")
	if err != nil {
		return // Silent fail, don't block startup
	}
	defer resp.Body.Close()
	
	var release struct {
		TagName string `json:"tag_name"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return
	}
	
	if release.TagName != "" && release.TagName != version {
		fmt.Printf("\n⚠️  Update available: %s → %s\n", version, release.TagName)
		fmt.Println("   Download: https://github.com/srsoumyax11/bee/releases/latest\n")
	}
}
