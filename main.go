package main

import (
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// Configuration
const (
	WgInterface  = "wg0"
	WgConfPath   = "/etc/wireguard/wg0.conf"
	PeersBaseDir = "/etc/wireguard/peers"
	ServerPort   = "13231" // Wireguard UDP port
	HttpPort     = ":8888" // Provisioning API port
	IpBase       = "10.30"
	IpHostMin    = 11
	IpHostMax    = 510
)

const (
	ServerEndpoint = "64.176.16.219"
	ServerPubKey   = "uJqo5zqckt9OYWZ0Y5+KaP20CLUhcKgkGJ+aqKTHCig="
)

// Mutex to prevent race conditions (two routers grabbing same IP)
var provisionMutex sync.Mutex

func main() {
	// Ensure directories exist
	os.MkdirAll(PeersBaseDir, 0755)

	http.HandleFunc("/provision", provisionHandler)

	log.Printf("Provisioning Server listening on %s", HttpPort)
	log.Fatal(http.ListenAndServe(HttpPort, nil))
}

func provisionHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Validate Serial
	serial := r.URL.Query().Get("serial")
	if !isValidSerial(serial) {
		http.Error(w, "Invalid or missing serial", http.StatusBadRequest)
		return
	}

	// 2. LOCK: Critical section starts here
	// This ensures only one request modifies the config at a time
	provisionMutex.Lock()
	defer provisionMutex.Unlock()

	peerDir := filepath.Join(PeersBaseDir, serial)
	mikrotikFile := filepath.Join(peerDir, fmt.Sprintf("mikrotik-%s.rsc", serial))

	// 3. IDEMPOTENCY: If script exists, return it immediately (don't create new keys)
	if _, err := os.Stat(mikrotikFile); err == nil {
		log.Printf("[%s] Configuration already exists. Returning cached script.", serial)
		content, _ := os.ReadFile(mikrotikFile)
		w.Header().Set("Content-Type", "text/plain")
		w.Write(content)
		return
	}

	log.Printf("[%s] New provisioning request.", serial)

	// 4. Find available IP
	clientIP, err := findNextAvailableIP()
	if err != nil {
		log.Printf("[%s] Error: %v", serial, err)
		http.Error(w, "No IPs available", http.StatusInternalServerError)
		return
	}

	// 5. Generate Keys
	privKey, pubKey, err := generateWireguardKeys()
	if err != nil {
		log.Printf("[%s] Keygen error: %v", serial, err)
		http.Error(w, "Key generation failed", http.StatusInternalServerError)
		return
	}

	// 6. Generate Random Port (20000 - 60000)
	listenPort := rand.Intn(40000) + 20000

	// 7. Update Server Config (wg0.conf)
	// We verify the server public key dynamically if needed, or use const
	serverPub := getInterfacePublicKey(WgInterface)
	
	newPeerConfig := fmt.Sprintf("\n[Peer]\n# Name: %s\nPublicKey = %s\nAllowedIPs = %s/32\n# Endpoint = <DYNAMIC>:%d\n", 
		serial, pubKey, clientIP, listenPort)

	f, err := os.OpenFile(WgConfPath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		log.Printf("Error opening wg config: %v", err)
		http.Error(w, "Server config error", http.StatusInternalServerError)
		return
	}
	if _, err = f.WriteString(newPeerConfig); err != nil {
		f.Close()
		http.Error(w, "Write error", http.StatusInternalServerError)
		return
	}
	f.Close()

	// 8. Apply Changes to WireGuard (The "wg addconf" equivalent)
	// Using bash -c to handle process substitution <() if necessary, 
	// but simpler is usually better. Your script used wg-quick strip.
	syncCmd := exec.Command("bash", "-c", fmt.Sprintf("wg addconf %s <(wg-quick strip %s)", WgInterface, WgInterface))
	if output, err := syncCmd.CombinedOutput(); err != nil {
		log.Printf("WireGuard Sync Error: %s", string(output))
		// Don't fail the request here, the file is written, but log it critical
	}

	// 9. Generate MikroTik Script Content
	scriptContent := fmt.Sprintf(`
/interface wireguard
add name=wg0 listen-port=%d private-key="%s"

/ip address
add address=%s/23 interface=wg0

/interface wireguard peers
add interface=wg0 public-key="%s" endpoint-address=%s endpoint-port=%s allowed-address=10.30.0.0/23 persistent-keepalive=25

/ip route
add dst-address=10.30.0.0/23 gateway=wg0
`, listenPort, privKey, clientIP, serverPub, ServerEndpoint, ServerPort)

	// 10. Save files and respond
	os.MkdirAll(peerDir, 0755)
	os.WriteFile(mikrotikFile, []byte(scriptContent), 0644)
	
	// Save client conf just in case (optional, based on your script)
	clientConf := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s/23\n...", privKey, clientIP)
	os.WriteFile(filepath.Join(peerDir, fmt.Sprintf("client-%s.conf", serial)), []byte(clientConf), 0644)

	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(scriptContent))
	
	log.Printf("[%s] Successfully provisioned IP: %s", serial, clientIP)
}

// --- Helpers ---

func findNextAvailableIP() (string, error) {
	// Read the current config to see what's taken
	confBytes, err := os.ReadFile(WgConfPath)
	if err != nil {
		return "", err
	}
	confString := string(confBytes)

	// Logic from your bash script: seq $IP_HOST_MIN 510
	for i := IpHostMin; i <= IpHostMax; i++ {
		oct1 := i / 256
		oct2 := i % 256
		candidate := fmt.Sprintf("%s.%d.%d", IpBase, oct1, oct2)

		// Simple string check (equivalent to grep -q)
		if !strings.Contains(confString, candidate) {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("no IPs available in range")
}

func generateWireguardKeys() (string, string, error) {
	// Priv Key
	cmdPriv := exec.Command("wg", "genkey")
	privOut, err := cmdPriv.Output()
	if err != nil {
		return "", "", err
	}
	privKey := strings.TrimSpace(string(privOut))

	// Pub Key
	cmdPub := exec.Command("wg", "pubkey")
	cmdPub.Stdin = strings.NewReader(privKey)
	pubOut, err := cmdPub.Output()
	if err != nil {
		return "", "", err
	}
	pubKey := strings.TrimSpace(string(pubOut))

	return privKey, pubKey, nil
}

func getInterfacePublicKey(iface string) string {
	//out, err := exec.Command("wg", "show", iface, "public-key").Output()
	//if err == nil {
	//	return strings.TrimSpace(string(out))
	//}
	return ServerPubKey
}

func isValidSerial(s string) bool {
	if s == "" {
		return false
	}
	// Alphanumeric only
	match, _ := regexp.MatchString("^[a-zA-Z0-9]+$", s)
	return match
}
