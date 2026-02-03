package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
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
	Asn             string                   `json:"asn,omitempty"`
	Org             string                   `json:"org,omitempty"`
	Versions        map[string]string        `json:"versions,omitempty"`
}

// HttpxResult matches the JSON output from httpx
type HttpxResult struct {
	Input      string   `json:"input"`
	Url        string   `json:"url"`
	StatusCode int      `json:"status_code"`
	Title      string   `json:"title"`
	Tech       []string `json:"tech"`
	WebServer  string   `json:"webserver"`
}

// AmassResult matches partial JSON output from amass
type AmassResult struct {
	Name      string `json:"name"`
	Domain    string `json:"domain"`
	Addresses []struct {
		Asn  int    `json:"asn"`
		Desc string `json:"desc"`
	} `json:"addresses"`
}

// WhatWebResult matches partial JSON output from whatweb
type WhatWebResult struct {
	Target  string `json:"target"`
	Plugins map[string]struct {
		String  []string `json:"string,omitempty"`
		Version []string `json:"version,omitempty"`
	} `json:"plugins"`
}

var (
	useDeep        bool
	useFingerprint bool
)

func main() {
	flag.BoolVar(&useDeep, "deep", false, "Enable deep discovery (Amass)")
	flag.BoolVar(&useFingerprint, "fingerprint", false, "Enable aggressive fingerprinting (WhatWeb)")
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s [-deep] [-fingerprint] <target-domain>\n", os.Args[0])
		os.Exit(1)
	}
	target := args[0]

	// Check if required tools are installed
	checkBinaries()

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Map to store ASN/Org info from Amass to enrich later
	// key: subdomain, value: struct{asn, org}
	type Infrastructure struct {
		Asn int
		Org string
	}
	infraMap := make(map[string]Infrastructure)
	var infraMutex sync.Mutex

	// Channel to collect subdomains from all sources
	subdomains := make(chan string, 1000)
	var wgDiscovery sync.WaitGroup

	// --- 1. Subfinder ---
	wgDiscovery.Add(1)
	go func() {
		defer wgDiscovery.Done()
		cmd := exec.Command("subfinder", "-d", target, "-silent")
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Subfinder pipe error: %v\n", err)
			return
		}
		if err := cmd.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "Subfinder start error: %v\n", err)
			return
		}
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			subdomains <- scanner.Text()
		}
		cmd.Wait()
	}()

	// --- 2. Amass (Conditional) ---
	if useDeep {
		wgDiscovery.Add(1)
		go func() {
			defer wgDiscovery.Done()
			// amass enum -passive -d target -json -
			// Note: Amass output format can be tricky. Using -passive for speed as requested in plan (though user said 'deep discovery' usually implies active, plan said 'amass enum -passive').
			// User request: "amass enum -passive -d <target>"
			// We stream output.
			cmd := exec.Command("amass", "enum", "-passive", "-d", target, "-json", "/dev/stdout") // forcing stdout if needed, or just let it print
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Amass pipe error: %v\n", err)
				return
			}
			if err := cmd.Start(); err != nil {
				fmt.Fprintf(os.Stderr, "Amass start error: %v\n", err)
				return
			}
			scanner := bufio.NewScanner(stdout)
			// Amass JSON output line by line
			for scanner.Scan() {
				line := scanner.Bytes()
				var ar AmassResult
				if err := json.Unmarshal(line, &ar); err == nil && ar.Name != "" {
					subdomains <- ar.Name
					// Capture Infra info
					if len(ar.Addresses) > 0 {
						infraMutex.Lock()
						infraMap[ar.Name] = Infrastructure{
							Asn: ar.Addresses[0].Asn,
							Org: ar.Addresses[0].Desc,
						}
						infraMutex.Unlock()
					}
				}
			}
			cmd.Wait()
		}()
	}

	// --- 3. Deduplication & Pipeline to Httpx ---
	// We need a way to close the input to httpx once discovery is done.
	// We'll use a pipe for httpx stdin.
	
	httpxCmd := exec.Command("httpx", "-silent", "-json", "-title", "-tech-detect", "-status-code")
	httpxIn, err := httpxCmd.StdinPipe()
	if err != nil {
		fatalError("Failed to create httpx stdin pipe", err)
	}
	httpxOut, err := httpxCmd.StdoutPipe()
	if err != nil {
		fatalError("Failed to create httpx stdout pipe", err)
	}

	if err := httpxCmd.Start(); err != nil {
		fatalError("Failed to start httpx", err)
	}

	// Nmap (Background)
	nmapCmd := exec.Command("nmap", "-F", "--top-ports", "100", target, "-oN", "nmap-scan.txt")
	if err := nmapCmd.Start(); err == nil {
		go nmapCmd.Wait()
	}

	// Discovery coordination routine
	go func() {
		wgDiscovery.Wait()
		close(subdomains)
	}()

	// Feed unique subdomains to httpx
	go func() {
		seen := make(map[string]bool)
		for sub := range subdomains {
			if !seen[sub] {
				seen[sub] = true
				fmt.Fprintln(httpxIn, sub)
			}
		}
		httpxIn.Close() // Signal httpx we are done sending targets
	}()

	// --- 4. Process Httpx Output & WhatWeb ---
	scanner := bufio.NewScanner(httpxOut)
	encoder := json.NewEncoder(os.Stdout)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		var hRes HttpxResult
		if err := json.Unmarshal(line, &hRes); err != nil {
			continue
		}

		// Prepare Result
		res := Result{
			Timestamp:       time.Now().Format(time.RFC3339),
			Subdomain:       hRes.Input,
			StatusCode:      hRes.StatusCode,
			Title:           hRes.Title,
			TechStack:       extractTech(hRes),
			Vulnerabilities: []map[string]interface{}{},
			Source:          "recon_pipeline",
		}

		// Enrich with Amass Infra Data
		infraMutex.Lock()
		if inf, ok := infraMap[hRes.Input]; ok {
			res.Asn = fmt.Sprintf("AS%d", inf.Asn)
			res.Org = inf.Org
		}
		infraMutex.Unlock()

		// --- 5. WhatWeb Fingerprinting (Conditional) ---
		if useFingerprint && hRes.StatusCode > 0 { // Only fingerprint live hosts
			// whatweb --aggression 3 --format=json <url>
			wwCmd := exec.Command("whatweb", "--aggression", "3", "--format=json", hRes.Url) // Use hRes.Url which has protocol
			// WhatWeb might take time, blocking here slows down the pipeline for this item.
			// Ideally we have a worker pool, but for now strict pipeline is safer for implementation simplicity.
			wwOut, err := wwCmd.Output()
			if err == nil {
				var wwResults []WhatWebResult
				if json.Unmarshal(wwOut, &wwResults) == nil && len(wwResults) > 0 {
					versions := make(map[string]string)
					for plugin, info := range wwResults[0].Plugins {
						if len(info.Version) > 0 {
							versions[plugin] = strings.Join(info.Version, ", ")
						}
					}
					res.Versions = versions
					
					// Also merge WhatWeb plugins into TechStack if not present?
					// Optional, but good for completeness.
					for plugin := range wwResults[0].Plugins {
						found := false
						for _, t := range res.TechStack {
							if t == plugin {
								found = true
								break
							}
						}
						if !found {
							res.TechStack = append(res.TechStack, plugin)
						}
					}
				}
			}
		}

		if err := encoder.Encode(res); err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding result: %v\n", err)
		}
	}

	httpxCmd.Wait()
}

func checkBinaries() {
	// nmap is allowed to be missing in some envs if only running partial, but let's check all as per requirement
	// Actually, if flags are off, we might not strictly need them, but for simplicity check all or just warn.
	// Requirement: "Add amass and whatweb to the bins slice"
	bins := []string{"subfinder", "httpx", "nmap"}
	if useDeep {
		bins = append(bins, "amass")
	}
	if useFingerprint {
		bins = append(bins, "whatweb")
	}

	for _, bin := range bins {
		if _, err := exec.LookPath(bin); err != nil {
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
	techs = append(techs, h.Tech...)
	return techs
}

func fatalError(msg string, err error) {
	fmt.Fprintf(os.Stderr, "Error: %s: %v\n", msg, err)
	os.Exit(1)
}
