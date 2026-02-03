package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"
)

// Result represents the unified data schema for recon results
type Result struct {
	Timestamp       string                   `json:"timestamp"`
	Subdomain       string                   `json:"subdomain"`
	StatusCode      int                      `json:"status_code"`
	Title           string                   `json:"title"`
	TechStack       []string                 `json:"tech_stack"`
	Vulnerabilities []map[string]interface{} `json:"vulnerabilities"`
	Source          string                   `json:"source"`
}

// HttpxResult matches the JSON output from httpx
type HttpxResult struct {
	Input      string `json:"input"`
	Url        string `json:"url"`
	StatusCode int    `json:"status_code"`
	Title      string `json:"title"`
	Tech       []struct {
		Name string `json:"name"`
	} `json:"tech"`
	WebServer []string `json:"webserver"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <target-domain>\n", os.Args[0])
		os.Exit(1)
	}
	target := os.Args[1]

	// Check if required tools are installed
	checkBinaries()

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Create command pipeline
	// subfinder -d target -silent
	subfinderCmd := exec.Command("subfinder", "-d", target, "-silent")

	// httpx -silent -json -title -tech-detect -status-code
	httpxCmd := exec.Command("httpx", "-silent", "-json", "-title", "-tech-detect", "-status-code")

	// Pipe subfinder stdout to httpx stdin
	reader, writer, err := os.Pipe()
	if err != nil {
		fatalError("Failed to create pipe", err)
	}
	subfinderCmd.Stdout = writer
	httpxCmd.Stdin = reader

	// Pipe httpx stdout to our processing
	httpxOut, err := httpxCmd.StdoutPipe()
	if err != nil {
		fatalError("Failed to get httpx stdout", err)
	}

	// Start subfinder
	if err := subfinderCmd.Start(); err != nil {
		fatalError("Failed to start subfinder", err)
	}

	// Start httpx
	if err := httpxCmd.Start(); err != nil {
		fatalError("Failed to start httpx", err)
	}

	// Close the writer end of the pipe after subfinder starts so httpx knows when input ends
	// We need to do this in a goroutine or after subfinder finishes,
	// but since we want streaming, we let subfinder write.
	// Actually, best pattern:
	// subfinder writes to pipe. When subfinder exit, close pipe. httpx reads EOF.
	go func() {
		defer writer.Close()
		subfinderCmd.Wait()
	}()

	// Handle graceful shutdown
	go func() {
		<-sigChan
		// Kill processes if they are running
		if subfinderCmd.Process != nil {
			subfinderCmd.Process.Kill()
		}
		if httpxCmd.Process != nil {
			httpxCmd.Process.Kill()
		}
		os.Exit(0)
	}()

	// Read and process httpx output
	scanner := bufio.NewScanner(httpxOut)
	encoder := json.NewEncoder(os.Stdout)

	// Increase max token size (httpx output can be large)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		var hRes HttpxResult
		if err := json.Unmarshal(line, &hRes); err != nil {
			continue // Skip malformed lines
		}

		// Transform to unified Result
		res := Result{
			Timestamp:       time.Now().Format(time.RFC3339),
			Subdomain:       hRes.Input,
			StatusCode:      hRes.StatusCode,
			Title:           hRes.Title,
			TechStack:       extractTech(hRes),
			Vulnerabilities: []map[string]interface{}{}, // Placeholder
			Source:          "recon_pipeline",
		}

		if err := encoder.Encode(res); err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding result: %v\n", err)
		}
	}

	httpxCmd.Wait()
}

func checkBinaries() {
	bins := []string{"subfinder", "httpx"}
	for _, bin := range bins {
		if _, err := exec.LookPath(bin); err != nil {
			// Output error as JSON so the UI displays it nicely?
			// Or just stderr. User asked for JSON-encoded error message to STDOUT.
			errRes := map[string]string{
				"error":   fmt.Sprintf("Missing binary: %s", bin),
				"message": "Please install required tools in PATH",
			}
			json.NewEncoder(os.Stdout).Encode(errRes)
			os.Exit(1)
		}
	}
}

func extractTech(h HttpxResult) []string {
	var techs []string
	for _, t := range h.Tech {
		techs = append(techs, t.Name)
	}
	// Append webserver if distinct? Usually httpx puts it in tech-detect too,
	// but let's just use what's in 'Tech' for now to be safe and clean.
	// If needed we can check h.WebServer
	return techs
}

func fatalError(msg string, err error) {
	fmt.Fprintf(os.Stderr, "Error: %s: %v\n", msg, err)
	os.Exit(1)
}
