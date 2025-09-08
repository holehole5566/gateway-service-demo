package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type GitHubUser struct {
	ID    int    `json:"id"`
	Login string `json:"login"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

type GoogleUser struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

type LineUser struct {
	UserID      string `json:"userId"`
	DisplayName string `json:"displayName"`
	PictureURL  string `json:"pictureUrl"`
	Email       string `json:"email"`
}

type Claims struct {
	UserID int    `json:"user_id"`
	Login  string `json:"login"`
	jwt.RegisteredClaims
}

var (
	githubClientID     = os.Getenv("GITHUB_CLIENT_ID")
	githubClientSecret = os.Getenv("GITHUB_CLIENT_SECRET")
	googleClientID     = os.Getenv("GOOGLE_CLIENT_ID")
	googleClientSecret = os.Getenv("GOOGLE_CLIENT_SECRET")
	lineClientID       = os.Getenv("LINE_CLIENT_ID")
	lineClientSecret   = os.Getenv("LINE_CLIENT_SECRET")
	jwtSecret          = []byte("demo-secret-key")
)

func main() {
	if githubClientID == "" || githubClientSecret == "" {
		log.Fatal("GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET must be set")
	}

	http.HandleFunc("/auth/login/github", handleGitHubLogin)
	http.HandleFunc("/auth/login/google", handleGoogleLogin)
	http.HandleFunc("/auth/login/line", handleLineLogin)
	http.HandleFunc("/auth/callback/github", handleGitHubCallback)
	http.HandleFunc("/auth/callback/google", handleGoogleCallback)
	http.HandleFunc("/auth/callback/line", handleLineCallback)
	http.HandleFunc("/auth/verify", handleVerify)

	// Enable CORS
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		
		if r.Method == "OPTIONS" {
			return
		}
		
		w.WriteHeader(http.StatusNotFound)
	})

	log.Println("Auth service running on :8081")
	log.Fatal(http.ListenAndServe(":8081", nil))
}

func handleGitHubLogin(w http.ResponseWriter, r *http.Request) {
	state := generateState()
	
	params := url.Values{}
	params.Add("client_id", githubClientID)
	params.Add("redirect_uri", "http://localhost:8081/auth/callback/github")
	params.Add("scope", "user:email")
	params.Add("state", state)
	
	authURL := "https://github.com/login/oauth/authorize?" + params.Encode()
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

func handleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	state := generateState()
	
	params := url.Values{}
	params.Add("client_id", googleClientID)
	params.Add("redirect_uri", "http://localhost:8081/auth/callback/google")
	params.Add("scope", "openid email profile")
	params.Add("response_type", "code")
	params.Add("state", state)
	
	authURL := "https://accounts.google.com/o/oauth2/v2/auth?" + params.Encode()
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

func handleLineLogin(w http.ResponseWriter, r *http.Request) {
	state := generateState()
	
	params := url.Values{}
	params.Add("response_type", "code")
	params.Add("client_id", lineClientID)
	params.Add("redirect_uri", "http://localhost:8081/auth/callback/line")
	params.Add("state", state)
	params.Add("scope", "profile openid email")
	
	authURL := "https://access.line.me/oauth2/v2.1/authorize?" + params.Encode()
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

func handleGitHubCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "No code provided", http.StatusBadRequest)
		return
	}

	// Exchange code for access token
	req, _ := http.NewRequest("POST", "https://github.com/login/oauth/access_token", nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	
	data := url.Values{}
	data.Set("client_id", githubClientID)
	data.Set("client_secret", githubClientSecret)
	data.Set("code", code)
	req.Body = http.NoBody
	req.URL.RawQuery = data.Encode()
	
	tokenResp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, "Failed to exchange code", http.StatusInternalServerError)
		return
	}
	defer tokenResp.Body.Close()

	var tokenData map[string]interface{}
	if err := json.NewDecoder(tokenResp.Body).Decode(&tokenData); err != nil {
		http.Error(w, "Failed to parse token response", http.StatusInternalServerError)
		return
	}
	
	accessToken, ok := tokenData["access_token"].(string)
	if !ok {
		log.Printf("Token response: %+v", tokenData)
		http.Error(w, "No access token received", http.StatusInternalServerError)
		return
	}

	// Get user info
	userReq, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
	userReq.Header.Set("Authorization", "Bearer "+accessToken)
	
	userResp, err := http.DefaultClient.Do(userReq)
	if err != nil {
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}
	defer userResp.Body.Close()

	var user GitHubUser
	json.NewDecoder(userResp.Body).Decode(&user)

	// Generate JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
		UserID: user.ID,
		Login:  user.Login,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	})

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Redirect to frontend with token
	userJSON, _ := json.Marshal(user)
	redirectURL := fmt.Sprintf("http://localhost:3000?token=%s&user=%s", 
		tokenString, url.QueryEscape(string(userJSON)))
	
	http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
}

func handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "No code provided", http.StatusBadRequest)
		return
	}

	// Exchange code for access token
	data := url.Values{}
	data.Set("client_id", googleClientID)
	data.Set("client_secret", googleClientSecret)
	data.Set("code", code)
	data.Set("grant_type", "authorization_code")
	data.Set("redirect_uri", "http://localhost:8081/auth/callback/google")
	
	tokenResp, err := http.PostForm("https://oauth2.googleapis.com/token", data)
	if err != nil {
		http.Error(w, "Failed to exchange code", http.StatusInternalServerError)
		return
	}
	defer tokenResp.Body.Close()

	var tokenData map[string]interface{}
	if err := json.NewDecoder(tokenResp.Body).Decode(&tokenData); err != nil {
		http.Error(w, "Failed to parse token response", http.StatusInternalServerError)
		return
	}
	
	accessToken, ok := tokenData["access_token"].(string)
	if !ok {
		http.Error(w, "No access token received", http.StatusInternalServerError)
		return
	}

	// Decode ID token to get user info
	idToken, ok := tokenData["id_token"].(string)
	if !ok {
		http.Error(w, "No ID token received", http.StatusInternalServerError)
		return
	}

	// Parse ID token (skip signature verification for demo)
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		http.Error(w, "Invalid ID token format", http.StatusInternalServerError)
		return
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		http.Error(w, "Failed to decode ID token", http.StatusInternalServerError)
		return
	}

	var user GoogleUser
	json.Unmarshal(payload, &user)

	// Generate JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
		UserID: 0, // Google uses string ID
		Login:  user.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	})

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Create user object for frontend
	userForFrontend := map[string]interface{}{
		"login": user.Email,
		"name":  user.Name,
		"email": user.Email,
	}
	userJSON, _ := json.Marshal(userForFrontend)
	redirectURL := fmt.Sprintf("http://localhost:3000?token=%s&user=%s", 
		tokenString, url.QueryEscape(string(userJSON)))
	
	http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
}

func handleLineCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "No code provided", http.StatusBadRequest)
		return
	}

	// Exchange code for access token
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", "http://localhost:8081/auth/callback/line")
	data.Set("client_id", lineClientID)
	data.Set("client_secret", lineClientSecret)
	
	tokenResp, err := http.PostForm("https://api.line.me/oauth2/v2.1/token", data)
	if err != nil {
		http.Error(w, "Failed to exchange code", http.StatusInternalServerError)
		return
	}
	defer tokenResp.Body.Close()

	var tokenData map[string]interface{}
	if err := json.NewDecoder(tokenResp.Body).Decode(&tokenData); err != nil {
		http.Error(w, "Failed to parse token response", http.StatusInternalServerError)
		return
	}
	
	accessToken, ok := tokenData["access_token"].(string)
	if !ok {
		http.Error(w, "No access token received", http.StatusInternalServerError)
		return
	}

	// Decode ID token to get user info
	idToken, ok := tokenData["id_token"].(string)
	if !ok {
		http.Error(w, "No ID token received", http.StatusInternalServerError)
		return
	}

	// Parse ID token (skip signature verification for demo)
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		http.Error(w, "Invalid ID token format", http.StatusInternalServerError)
		return
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		http.Error(w, "Failed to decode ID token", http.StatusInternalServerError)
		return
	}

	var tokenPayload map[string]interface{}
	json.Unmarshal(payload, &tokenPayload)

	var user LineUser
	if name, ok := tokenPayload["name"].(string); ok {
		user.DisplayName = name
	}
	if email, ok := tokenPayload["email"].(string); ok {
		user.Email = email
	}
	if sub, ok := tokenPayload["sub"].(string); ok {
		user.UserID = sub
	}

	// Generate JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
		UserID: 0, // Line uses string ID
		Login:  user.DisplayName,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	})

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Create user object for frontend
	userForFrontend := map[string]interface{}{
		"login": user.DisplayName,
		"name":  user.DisplayName,
		"email": user.Email,
	}
	userJSON, _ := json.Marshal(userForFrontend)
	redirectURL := fmt.Sprintf("http://localhost:3000?token=%s&user=%s", 
		tokenString, url.QueryEscape(string(userJSON)))
	
	http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
}

func handleVerify(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")
	
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "No token provided"})
		return
	}

	tokenString := authHeader[7:] // Remove "Bearer "
	
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid token"})
		return
	}

	claims := token.Claims.(*Claims)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"valid":   true,
		"user_id": claims.UserID,
		"login":   claims.Login,
	})
}

func generateState() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}