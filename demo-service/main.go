package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
)

type Response struct {
	Message   string                 `json:"message"`
	Timestamp string                 `json:"timestamp"`
	Service   string                 `json:"service"`
	Headers   map[string]interface{} `json:"headers,omitempty"`
}

func main() {
	http.HandleFunc("/public", handlePublic)
	http.HandleFunc("/private", handlePrivate)
	http.HandleFunc("/user", handleUser)

	// Enable CORS
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-User-ID, X-User-Login")
		
		if r.Method == "OPTIONS" {
			return
		}
		
		w.WriteHeader(http.StatusNotFound)
	})

	log.Println("Demo service running on :8082")
	log.Fatal(http.ListenAndServe(":8082", nil))
}

func handlePublic(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	response := Response{
		Message:   "This is a public endpoint - no authentication required",
		Timestamp: time.Now().Format(time.RFC3339),
		Service:   "demo-service",
	}
	
	json.NewEncoder(w).Encode(response)
}

func handlePrivate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	// Check for user headers added by gateway
	userID := r.Header.Get("X-User-ID")
	userIDStr := r.Header.Get("X-User-ID-Str")
	userLogin := r.Header.Get("X-User-Login")
	userEmail := r.Header.Get("X-User-Email")
	
	headers := make(map[string]interface{})
	if userID != "" {
		headers["X-User-ID"] = userID
	}
	if userIDStr != "" {
		headers["X-User-ID-Str"] = userIDStr
	}
	if userLogin != "" {
		headers["X-User-Login"] = userLogin
	}
	if userEmail != "" {
		headers["X-User-Email"] = userEmail
	}
	
	response := Response{
		Message:   "This is a private endpoint - authentication required",
		Timestamp: time.Now().Format(time.RFC3339),
		Service:   "demo-service",
		Headers:   headers,
	}
	
	json.NewEncoder(w).Encode(response)
}

func handleUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	userID := r.Header.Get("X-User-ID")
	userIDStr := r.Header.Get("X-User-ID-Str")
	userLogin := r.Header.Get("X-User-Login")
	userEmail := r.Header.Get("X-User-Email")
	
	if userLogin == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Missing user information in headers",
		})
		return
	}
	
	headers := map[string]interface{}{
		"X-User-ID":    userID,
		"X-User-Login": userLogin,
	}
	if userIDStr != "" {
		headers["X-User-ID-Str"] = userIDStr
	}
	if userEmail != "" {
		headers["X-User-Email"] = userEmail
	}
	
	response := Response{
		Message:   "User-specific data retrieved successfully",
		Timestamp: time.Now().Format(time.RFC3339),
		Service:   "demo-service",
		Headers:   headers,
	}
	
	json.NewEncoder(w).Encode(response)
}