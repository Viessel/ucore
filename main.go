package main

import (
	"fmt"
	"log"
	//"math/rand"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
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

func provision(serial string, w http.ResponseWriter) {
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

	listenPort := 12321

	// 7. Update Server Config (wg0.conf)
	// We verify the server public key dynamically if needed, or use const
	serverPub := ServerPubKey

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

func isValidSerial(s string) bool {
	if s == "" {
		return false
	}
	// Alphanumeric only
	match, _ := regexp.MatchString("^[a-zA-Z0-9]+$", s)
	return match
}

const (
	GLPIBaseURL = "http://127.0.0.1:8080/api.php/v1"

	AppToken  = "02sq17hxC1Iy7yIbTklrZsNSitUonXs2TSoptkL9"
	UserToken = "rfkgPlcZzfQuHwsksB4VNoISdVwE1KDKUbJ2DKck"

	StatePending  = 1 // Estado "Nuevo / Pendiente"
	StateApproved = 2 // Estado "En Producción / Aprobado"
)

// Estructuras (Structs) para leer el JSON de GLPI
type SessionResponse struct {
	SessionToken string `json:"session_token"`
}

type NetworkEquipment struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Serial   string `json:"serial"`
	StatesID any    `json:"states_id"` // Usamos interface{} porque a veces GLPI devuelve string o int
}

// Handler principal que recibe la petición del Mikrotik
func provisionHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Obtener Serial de la URL (ej: ?serial=XYZ)

	serial := r.URL.Query().Get("serial")
	if !isValidSerial(serial) {
		http.Error(w, "Invalid or missing serial", http.StatusBadRequest)
		return
	}
	log.Printf("Procesando serial: %s", serial)

	// 2. Login en GLPI (Obtener Session-Token)
	sessionToken, err := glpiLogin()
	if err != nil {
		log.Printf("Error login GLPI: %v", err)
		http.Error(w, "# Error interno conectando a inventario", http.StatusInternalServerError)
		return
	}
	log.Printf("Session token: %v", sessionToken)
	// Al terminar, cerramos sesión para no saturar GLPI
	//defer glpiKillSession(sessionToken)

	
	// 3. Buscar el dispositivo por Serial
	device, err := glpiFindDevice(sessionToken, serial)
	if err != nil {
		log.Printf("Error buscando dispositivo: %v", err)
		return
	}

	// 4. Lógica de Aprobación

	// CASO A: No existe -> Lo creamos como pendiente
	if device == nil {
		log.Printf("Serial %s no encontrado. Creando nuevo registro...", serial)
		err := glpiCreateDevice(sessionToken, serial)
		if err != nil {
			log.Printf("Error creando dispositivo: %v", err)
			fmt.Fprintf(w, "# Error registrando dispositivo en inventario")
			return
		}
		// Respuesta al Mikrotik: No hacer nada aún
		fmt.Fprintf(w, "# Dispositivo registrado exitosamente. Esperando aprobacion del administrador.")
		return
	}

	// CASO B: Existe -> Verificamos si está aprobado
	// Convertimos el ID de estado a entero para comparar
	currentState := toInt(device.StatesID)
	log.Printf("Dispositivo encontrado (ID: %d), Estado: %d", device.ID, currentState)

	if currentState == StateApproved {
		// ¡APROBADO! -> Enviamos el script de configuración real
		config := generateWireguardConfig(serial)
		fmt.Fprint(w, config)
	} else {
		// PENDIENTE -> Decimos al Mikrotik que espere
		fmt.Fprintf(w, "# Dispositivo conocido pero en estado %d (No aprobado). Esperando...", currentState)
	}
}

// --- FUNCIONES AUXILIARES GLPI ---

func glpiLogin() (string, error) {
	// Endpoint: /initSession
	req, _ := http.NewRequest("GET", GLPIBaseURL+"/initSession", nil)
	req.Header.Set("App-Token", AppToken)
	req.Header.Set("Authorization", "user_token "+UserToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("login fallido (%d): %s", resp.StatusCode, string(body))
	}

	var result SessionResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	return result.SessionToken, nil
}

func glpiKillSession(token string) {
	req, _ := http.NewRequest("GET", GLPIBaseURL+"/killSession", nil)
	req.Header.Set("App-Token", AppToken)
	req.Header.Set("Session-Token", token)
	(&http.Client{}).Do(req)
}

func glpiFindDevice(token, serial string) (*NetworkEquipment, error) {
	// Buscamos en el endpoint /NetworkEquipment
	// Usamos query params para filtrar por serial
	baseURL, _ := url.Parse(GLPIBaseURL + "/NetworkEquipment")
	params := url.Values{}
	params.Add("searchText[serial]", serial) // Filtro simple (puede variar según versión exacta)
	// Si el filtro anterior falla en tu versión, usa solo "searchText":
	// params.Add("searchText", serial)

	baseURL.RawQuery = params.Encode()

	req, _ := http.NewRequest("GET", baseURL.String(), nil)
	req.Header.Set("App-Token", AppToken)
	req.Header.Set("Session-Token", token)

	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// GLPI puede devolver un array o un error si no encuentra nada
	if resp.StatusCode != 200 && resp.StatusCode != 206 {
		return nil, nil // Asumimos no encontrado o error de permisos
	}

	var devices []NetworkEquipment
	// Intentamos decodificar como array
	if err := json.NewDecoder(resp.Body).Decode(&devices); err != nil {
		return nil, nil // No se pudo parsear, probablemente vacío o formato distinto
	}

	// Buscamos coincidencia exacta (por si searchText fue "fuzzy")
	for _, d := range devices {
		if d.Serial == serial {
			return &d, nil
		}
	}

	return nil, nil
}

func glpiCreateDevice(token, serial string) error {
	// JSON para crear el equipo
	payload := map[string]any{
		"input": []map[string]any{{
			"name":      "Mikrotik-" + serial,
			"serial":    serial,
			"states_id": StatePending,
		},
	}}
	jsonPayload, _ := json.Marshal(payload)

	req, _ := http.NewRequest("POST", GLPIBaseURL+"/NetworkEquipment", bytes.NewBuffer(jsonPayload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("App-Token", AppToken)
	req.Header.Set("Session-Token", token)

	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 { // 201 Created es el éxito estándar
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// Helper para manejar IDs que vienen como float/string/int
func toInt(val any) int {
	switch v := val.(type) {
	case int:
		return v
	case float64:
		return int(v)
	default:
		return 0
	}
}

// --- GENERADOR DE CONFIGURACIÓN ---
func generateWireguardConfig(serial string) string {
	// Aquí personalizas la respuesta final para el Mikrotik
	return fmt.Sprintf(`
/interface wireguard add name=wg0 listen-port=13231
/ip address add address=10.10.50.5/24 interface=wg0
:log info "Provisioning completado para %s"
`, serial)
}
