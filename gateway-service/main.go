package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

type AuthResponse struct {
	Valid  bool `json:"valid"`
	UserID int  `json:"user_id"`
	Login  string `json:"login"`
}

type Gateway struct {
	authServiceURL  string
	demoServiceURL  string
}

func main() {
	// Load .env file
	if err := godotenv.Load(); err != nil {
		log.Printf("Warning: .env file not found: %v", err)
	}

	gateway := &Gateway{
		authServiceURL: getEnv("AUTH_SERVICE_URL", "http://localhost:8081"),
		demoServiceURL: getEnv("DEMO_SERVICE_URL", "http://localhost:8082"),
	}

	log.Printf("Config: AUTH_SERVICE_URL=%s, DEMO_SERVICE_URL=%s", gateway.authServiceURL, gateway.demoServiceURL)

	http.HandleFunc("/api/", gateway.handleAPI)
	
	// Enable CORS
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		
		if r.Method == "OPTIONS" {
			return
		}
		
		w.WriteHeader(http.StatusNotFound)
	})

	log.Println("Gateway service running on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func (g *Gateway) handleAPI(w http.ResponseWriter, r *http.Request) {
	// Enable CORS
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	
	if r.Method == "OPTIONS" {
		return
	}

	// Log incoming request
	log.Printf("Gateway: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
	
	// Extract endpoint
	path := strings.TrimPrefix(r.URL.Path, "/api")
	
	// Validate request headers
	if err := g.validateHeaders(r); err != nil {
		log.Printf("Header validation failed: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	// Check if authentication is required
	requiresAuth := path != "/public"
	
	var userID int
	var userLogin string
	
	if requiresAuth {
		authResp, err := g.validateToken(r)
		if err != nil {
			log.Printf("Authentication failed: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Authentication required"})
			return
		}
		
		userID = authResp.UserID
		userLogin = authResp.Login
		log.Printf("Authenticated user: %s (ID: %d)", userLogin, userID)
	}

	// Proxy request to demo service
	g.proxyRequest(w, r, path, userID, userLogin)
}

func (g *Gateway) validateHeaders(r *http.Request) error {
	// Example header validation
	contentType := r.Header.Get("Content-Type")
	if r.Method == "POST" || r.Method == "PUT" {
		if contentType != "" && !strings.Contains(contentType, "application/json") {
			return fmt.Errorf("invalid content-type: %s", contentType)
		}
	}
	
	// Check for required custom headers (example)
	if r.Header.Get("User-Agent") == "" {
		log.Printf("Warning: No User-Agent header")
	}
	
	return nil
}

func (g *Gateway) validateToken(r *http.Request) (*AuthResponse, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, fmt.Errorf("no authorization header")
	}

	log.Printf("Validating token: %s...", authHeader[:min(len(authHeader), 20)])

	// Forward auth request to auth service
	req, err := http.NewRequest("GET", g.authServiceURL+"/auth/verify", nil)
	if err != nil {
		return nil, err
	}
	
	req.Header.Set("Authorization", authHeader)
	
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Auth service request failed: %v", err)
		return nil, err
	}
	defer resp.Body.Close()
	
	log.Printf("Auth service response: %d", resp.StatusCode)
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("authentication failed")
	}
	
	var authResp AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return nil, err
	}
	
	return &authResp, nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (g *Gateway) proxyRequest(w http.ResponseWriter, r *http.Request, path string, userID int, userLogin string) {
	// Parse target URL
	target, err := url.Parse(g.demoServiceURL)
	if err != nil {
		log.Printf("Failed to parse target URL: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Create reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(target)
	
	// Modify request before forwarding
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.URL.Path = path
		
		// Add user information as headers
		if userID != 0 {
			req.Header.Set("X-User-ID", strconv.Itoa(userID))
			req.Header.Set("X-User-Login", userLogin)
		}
		
		// Add gateway metadata
		req.Header.Set("X-Gateway-Timestamp", time.Now().Format(time.RFC3339))
		req.Header.Set("X-Forwarded-By", "gateway-service")
		
		log.Printf("Proxying to: %s", req.URL.String())
	}
	
	// Modify response
	proxy.ModifyResponse = func(resp *http.Response) error {
		// Add gateway headers to response
		resp.Header.Set("X-Gateway-Version", "1.0")
		resp.Header.Set("X-Processed-At", time.Now().Format(time.RFC3339))
		
		// Log response
		log.Printf("Response: %d from %s", resp.StatusCode, resp.Request.URL.String())
		
		return nil
	}
	
	// Handle errors
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("Proxy error: %v", err)
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Service unavailable",
		})
	}
	
	proxy.ServeHTTP(w, r)
}