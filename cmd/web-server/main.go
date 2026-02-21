package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"

	"log-analyser/pkg/api"
)

func main() {
	port := "8080"
	if p := os.Getenv("PORT"); p != "" {
		port = p
	}

	// Locate web/ directory relative to this binary's source location.
	// During development `go run` the CWD is typically the project root.
	_, thisFile, _, _ := runtime.Caller(0)
	projectRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")
	webDir := filepath.Join(projectRoot, "web")

	// Fallback: check cwd/web
	if _, err := os.Stat(webDir); os.IsNotExist(err) {
		cwd, _ := os.Getwd()
		webDir = filepath.Join(cwd, "web")
	}

	fmt.Printf("📡 Wireshark GSM_MAP/TCAP/SCP Analyser\n")
	fmt.Printf("   Serving frontend from: %s\n", webDir)
	fmt.Printf("   Listening on http://localhost:%s\n\n", port)
	fmt.Printf("   Export from Wireshark:\n")
	fmt.Printf("     tshark -r capture.pcap -T pdml > capture.pdml\n")
	fmt.Printf("     tshark -r capture.pcap -T json > capture.json\n\n")

	router := api.NewRouter(webDir)
	if err := http.ListenAndServe(":"+port, router); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
