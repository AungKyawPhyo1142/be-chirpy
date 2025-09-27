package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/AungKyawPhyo1142/chirpy/handlers"
	"github.com/AungKyawPhyo1142/chirpy/internal/database"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"

	"encoding/json"
	"log"

	"github.com/AungKyawPhyo1142/chirpy/helpers"
	"github.com/google/uuid"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	DB             *database.Queries
	Platfrom       string
}

func (api *apiConfig) HandlerMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	hits := fmt.Sprintf(`<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>`, api.fileserverHits.Load())
	w.Write([]byte(hits))
}

func (api *apiConfig) HandlerResetHits(w http.ResponseWriter, r *http.Request) {
	api.fileserverHits.Store(0)
}

// middleware on apiConfig
func (api *apiConfig) middlewareMetricInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		api.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

type CreateUserRequest struct {
	Email string `json:"email"`
}

type UserResponse struct {
	ID        uuid.UUID `json:"id"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (api *apiConfig) CreateUserHandler(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	reqBody := CreateUserRequest{}

	if err := decoder.Decode(&reqBody); err != nil {
		log.Printf("error decoding request body: %s", err)
		helpers.ResponseWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	user, err := api.DB.CreateUser(r.Context(), reqBody.Email)
	if err != nil {
		log.Printf("error creating user: %s", err)
		helpers.ResponseWithError(w, http.StatusInternalServerError, "Couldn't create user")
		return
	}

	response := UserResponse{
		ID:        user.ID,
		Email:     user.Email,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}

	helpers.ResponseWithJSON(w, http.StatusCreated, response)
}

func (api *apiConfig) HandlerResetUsers(w http.ResponseWriter, r *http.Request) {
	if api.Platfrom != "dev" {
		helpers.ResponseWithError(w, http.StatusForbidden, "Forbidden platfrom!")
		return
	}

	if err := api.DB.DeleteAllUsers(r.Context()); err != nil {
		log.Printf("error deleting users: %s", err)
		helpers.ResponseWithError(w, http.StatusInternalServerError, "Couldn't delete users")
		return
	}

	helpers.ResponseWithJSON(w, http.StatusOK, struct{}{})

}

func main() {
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	if dbURL == "" {
		panic("DB_URL is not set")
	}

	platform := os.Getenv("PLATFORM")
	if platform == "" {
		panic("PLATFORM is not set")
	}

	dbConnection, err := sql.Open("postgres", dbURL)
	if err != nil {
		panic(err)
	}
	dbQueries := database.New(dbConnection)

	mux := http.NewServeMux()
	apiCfg := &apiConfig{
		fileserverHits: atomic.Int32{},
		DB:             dbQueries,
		Platfrom:       platform,
	}

	var server http.Server
	server.Handler = mux
	server.Addr = ":8080"

	mux.Handle("/app/", apiCfg.middlewareMetricInc((http.StripPrefix("/app", http.FileServer(http.Dir("./"))))))
	mux.HandleFunc("GET /admin/metrics", apiCfg.HandlerMetrics)
	mux.HandleFunc("POST /admin/reset", apiCfg.HandlerResetUsers)
	mux.HandleFunc("GET /api/healthz", handlers.HandlerReady)
	mux.HandleFunc("POST /api/chirps", handlers.HandlerValidateChirp)
	mux.HandleFunc("POST /api/users", apiCfg.CreateUserHandler)

	server.ListenAndServe()

}
