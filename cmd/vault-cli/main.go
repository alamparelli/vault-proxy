package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/alamparelli/vault-proxy/pkg/client"
	"golang.org/x/term"
)

var cliHTTPClient = &http.Client{Timeout: 60 * time.Second}

const sessionFile = ".vault-proxy/session"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	// Multi-call binary: detect invocation name for ALF integration
	// When symlinked as "vault" in tools.d/, supports shorthand:
	//   vault proxy <service> <method> <path> [body]
	bin := filepath.Base(os.Args[0])
	if bin == "vault" && len(os.Args) >= 2 && os.Args[1] == "proxy" {
		proxyShorthand(os.Args[2:])
		return
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "unlock":
		cmdUnlock(args)
	case "lock":
		cmdLock()
	case "service":
		if len(args) == 0 {
			fmt.Fprintln(os.Stderr, "usage: vault-cli service <list|add|remove>")
			os.Exit(1)
		}
		switch args[0] {
		case "list":
			cmdServiceList()
		case "add":
			cmdServiceAdd(args[1:])
		case "remove":
			cmdServiceRemove(args[1:])
		default:
			fmt.Fprintf(os.Stderr, "unknown service command: %s\n", args[0])
			os.Exit(1)
		}
	case "file":
		if len(args) == 0 {
			fmt.Fprintln(os.Stderr, "usage: vault-cli file <upload|list|download|delete>")
			os.Exit(1)
		}
		switch args[0] {
		case "upload":
			cmdFileUpload(args[1:])
		case "list":
			cmdFileList()
		case "download":
			cmdFileDownload(args[1:])
		case "delete":
			cmdFileDelete(args[1:])
		default:
			fmt.Fprintf(os.Stderr, "unknown file command: %s\n", args[0])
			os.Exit(1)
		}
	case "http":
		cmdHTTP(args)
	case "proxy":
		proxyShorthand(args)
	case "token":
		if len(args) == 0 {
			fmt.Fprintln(os.Stderr, "usage: vault-cli token <create|list|revoke>")
			os.Exit(1)
		}
		switch args[0] {
		case "create":
			cmdTokenCreate(args[1:])
		case "list":
			cmdTokenList()
		case "revoke":
			cmdTokenRevoke(args[1:])
		default:
			fmt.Fprintf(os.Stderr, "unknown token command: %s\n", args[0])
			os.Exit(1)
		}
	case "health":
		cmdHealth()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `vault-cli — secrets vault CLI

Commands:
  health                  Check vault server status
  unlock                  Authenticate and get session token
  lock                    Lock the vault
  service list            List configured services
  service add <json>      Add/update a service (JSON on stdin or arg)
  service remove <name>   Remove a service
  file upload <name> <path>  Upload a file to the vault
  file list                  List stored files
  file download <name> [out] Download a file from the vault
  file delete <name>         Delete a file from the vault
  http                    Proxy an HTTP request (--service, --method, --path, --body)
  proxy <svc> <M> <path> [body]  Shorthand proxy (for AI agents)
  token create [scope]    Create a session token (admin|proxy, default: proxy)
  token list              List active tokens
  token revoke <id>       Revoke a token

Environment:
  VAULT_ADDR    Server address (default: http://127.0.0.1:8390)
  VAULT_TOKEN   Session token (overrides ~/.vault-proxy/session)`)
}

func newClient() *client.Client {
	c := client.New()
	if c.Token == "" {
		home, _ := os.UserHomeDir()
		if home != "" {
			data, err := os.ReadFile(filepath.Join(home, sessionFile))
			if err == nil {
				c.Token = strings.TrimSpace(string(data))
			}
		}
	}
	return c
}

func saveSession(token string) {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	dir := filepath.Join(home, ".vault-proxy")
	os.MkdirAll(dir, 0700)
	os.WriteFile(filepath.Join(dir, "session"), []byte(token), 0600)
}

func clearSession() {
	home, _ := os.UserHomeDir()
	if home != "" {
		os.Remove(filepath.Join(home, sessionFile))
	}
}

// --- Commands ---

func cmdHealth() {
	c := client.New()
	status, err := c.Health()
	if err != nil {
		fmt.Fprintf(os.Stderr, "vault-server unreachable: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("vault: %s\n", status)
}

func cmdUnlock(args []string) {
	// Never accept password as CLI arg (visible in ps aux / shell history)
	fmt.Fprint(os.Stderr, "Master password: ")
	raw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr) // newline after hidden input
	if err != nil {
		fmt.Fprintf(os.Stderr, "read password: %v\n", err)
		os.Exit(1)
	}
	password := string(raw)

	c := client.New()
	token, err := c.Unlock(password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "unlock failed: %v\n", err)
		os.Exit(1)
	}

	saveSession(token)
	fmt.Println("Vault unlocked. Session saved.")
}

func cmdLock() {
	c := newClient()
	if err := c.Lock(); err != nil {
		fmt.Fprintf(os.Stderr, "lock failed: %v\n", err)
		os.Exit(1)
	}
	clearSession()
	fmt.Println("Vault locked.")
}

func cmdServiceList() {
	c := newClient()
	services, err := c.ListServices()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if len(services) == 0 {
		fmt.Println("No services configured.")
		return
	}
	for _, s := range services {
		fmt.Printf("  %-20s %s (%s)\n", s.Name, s.BaseURL, s.AuthType)
	}
}

func cmdServiceAdd(args []string) {
	var jsonData string
	if len(args) > 0 {
		jsonData = args[0]
	} else {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read stdin: %v\n", err)
			os.Exit(1)
		}
		jsonData = string(data)
	}

	c := newClient()
	resp, err := doRaw(c, "POST", "/services", strings.NewReader(jsonData))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		io.Copy(os.Stderr, resp.Body)
		fmt.Fprintln(os.Stderr)
		os.Exit(1)
	}
	fmt.Println("Service added.")
}

func cmdServiceRemove(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: vault-cli service remove <name>")
		os.Exit(1)
	}

	c := newClient()
	resp, err := doRaw(c, "DELETE", "/services/"+args[0], nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		io.Copy(os.Stderr, resp.Body)
		fmt.Fprintln(os.Stderr)
		os.Exit(1)
	}
	fmt.Println("Service removed.")
}

func cmdHTTP(args []string) {
	var service, method, path, body string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--service", "-s":
			i++
			if i < len(args) {
				service = args[i]
			}
		case "--method", "-m":
			i++
			if i < len(args) {
				method = args[i]
			}
		case "--path", "-p":
			i++
			if i < len(args) {
				path = args[i]
			}
		case "--body", "-b":
			i++
			if i < len(args) {
				body = args[i]
			}
		}
	}

	if service == "" || method == "" || path == "" {
		fmt.Fprintln(os.Stderr, "usage: vault-cli http --service <name> --method <M> --path <path> [--body <json>]")
		os.Exit(1)
	}

	doProxy(service, method, path, body)
}

func proxyShorthand(args []string) {
	if len(args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: vault proxy <service> <method> <path> [body]")
		os.Exit(1)
	}

	service := args[0]
	method := strings.ToUpper(args[1])
	path := args[2]
	body := ""
	if len(args) > 3 {
		body = args[3]
	}
	if body == "-" {
		data, _ := io.ReadAll(os.Stdin)
		body = string(data)
	}

	doProxy(service, method, path, body)
}

func doProxy(service, method, path, body string) {
	c := newClient()

	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	resp, err := c.Proxy(service, method, path, bodyReader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "proxy error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	io.Copy(os.Stdout, resp.Body)

	if resp.StatusCode >= 400 {
		os.Exit(1)
	}
}

func cmdTokenCreate(args []string) {
	scope := "proxy"
	if len(args) > 0 {
		scope = args[0]
	}

	c := newClient()
	token, err := c.CreateToken(scope)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(token)
}

func cmdTokenList() {
	c := newClient()
	resp, err := doRaw(c, "GET", "/tokens", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	io.Copy(os.Stdout, resp.Body)
}

func cmdTokenRevoke(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: vault-cli token revoke <id>")
		os.Exit(1)
	}

	c := newClient()
	resp, err := doRaw(c, "DELETE", "/tokens/"+args[0], nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	resp.Body.Close()

	if resp.StatusCode >= 400 {
		fmt.Fprintln(os.Stderr, "revoke failed")
		os.Exit(1)
	}
	fmt.Println("Token revoked.")
}

// --- File commands ---

func cmdFileUpload(args []string) {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: vault-cli file upload <name> <path>")
		os.Exit(1)
	}
	name := args[0]
	path := args[1]

	c := newClient()
	if err := c.UploadFile(name, path); err != nil {
		fmt.Fprintf(os.Stderr, "upload failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("File %q uploaded.\n", name)
}

func cmdFileList() {
	c := newClient()
	files, err := c.ListFiles()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if len(files) == 0 {
		fmt.Println("No files stored.")
		return
	}
	for _, f := range files {
		fmt.Printf("  %-30s %s (%d bytes)\n", f.Name, f.MimeType, f.Size)
	}
}

func cmdFileDownload(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: vault-cli file download <name> [output]")
		os.Exit(1)
	}
	name := args[0]
	output := name
	if len(args) > 1 {
		output = args[1]
	}

	c := newClient()
	data, err := c.GetFile(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "download failed: %v\n", err)
		os.Exit(1)
	}

	if output == "-" {
		os.Stdout.Write(data)
		return
	}

	if err := os.WriteFile(output, data, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "write file: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("File %q saved to %s (%d bytes)\n", name, output, len(data))
}

func cmdFileDelete(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: vault-cli file delete <name>")
		os.Exit(1)
	}

	c := newClient()
	if err := c.DeleteFile(args[0]); err != nil {
		fmt.Fprintf(os.Stderr, "delete failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("File deleted.")
}

func doRaw(c *client.Client, method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, c.Addr+path, body)
	if err != nil {
		return nil, err
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return cliHTTPClient.Do(req)
}
