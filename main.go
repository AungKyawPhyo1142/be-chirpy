package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/AungKyawPhyo1142/chirpy/handlers"
	"github.com/AungKyawPhyo1142/chirpy/internal/auth"
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
	JWTSecret      string
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

// ------------------- Auth --------------------------
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResponse struct {
	ID           string    `json:"id"`
	Email        string    `json:"email"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Token        string    `json:"token"`
	RefreshToken string    `json:"refresh_token"`
}

func (api *apiConfig) LoginHandler(w http.ResponseWriter, r *http.Request) {

	decoder := json.NewDecoder(r.Body)
	parsed := LoginRequest{}

	if err := decoder.Decode(&parsed); err != nil {
		log.Printf("error decoding request body: %s", err)
		helpers.ResponseWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	dbUser, err := api.DB.GetUserByEmail(r.Context(), parsed.Email)
	if err == sql.ErrNoRows {
		helpers.ResponseWithError(w, http.StatusUnauthorized, "Incorrect email or password")
		return
	} else if err != nil {
		log.Printf("error getting user: %s", err)
		helpers.ResponseWithError(w, http.StatusInternalServerError, "Couldn't get user")
		return
	}

	authorized, err := auth.CheckPasswordHash(parsed.Password, dbUser.HashedPassword)
	if err != nil {
		log.Printf("error checking password: %s", err)
		helpers.ResponseWithError(w, http.StatusInternalServerError, "Couldn't check password")
		return
	}

	if !authorized {
		helpers.ResponseWithError(w, http.StatusUnauthorized, "Incorrect email or password")
		return
	}

	token, err := auth.MakeJWT(dbUser.ID, api.JWTSecret, time.Hour)
	if err != nil {
		log.Printf("error making token: %s", err)
		helpers.ResponseWithError(w, http.StatusInternalServerError, "Couldn't make JWT token")
		return
	}

	refreshToken, err := auth.MakeRefreshToken()
	if err != nil {
		log.Printf("error making refresh token: %s", err)
		helpers.ResponseWithError(w, http.StatusInternalServerError, "Couldn't make refresh token")
		return
	}

	dbRefreshToken, err := api.DB.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{
		Token:     refreshToken,
		UserID:    dbUser.ID,
		ExpiresAt: time.Now().Add(time.Hour * 24 * 60),
	})

	response := LoginResponse{
		ID:           dbUser.ID.String(),
		Email:        dbUser.Email,
		CreatedAt:    dbUser.CreatedAt,
		UpdatedAt:    dbUser.UpdatedAt,
		Token:        token,
		RefreshToken: dbRefreshToken.Token,
	}

	helpers.ResponseWithJSON(w, http.StatusOK, response)

}

func (api *apiConfig) RefreshHandler(w http.ResponseWriter, r *http.Request) {

	refreshToken, err := auth.GetRefreshToken(r.Header)
	if err != nil {
		log.Printf("error getting refresh token: %v", err)
		helpers.ResponseWithError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	dbRefreshToken, err := api.DB.GetRefreshToken(r.Context(), refreshToken)
	if err == sql.ErrNoRows {
		helpers.ResponseWithError(w, http.StatusUnauthorized, "Refresh Token Not Found!")
		return
	}

	if dbRefreshToken.ExpiresAt.Before(time.Now()) {
		helpers.ResponseWithError(w, http.StatusUnauthorized, "Refresh Token Expired")
		return
	}

	if dbRefreshToken.RevokedAt.Valid {
		helpers.ResponseWithError(w, http.StatusUnauthorized, "Refresh Token Revoked")
		return
	}

	dbUser, err := api.DB.GetUserFromRefreshToken(r.Context(), dbRefreshToken.Token)
	if err != nil {
		log.Printf("error getting user from refresh token: %v", err)
		helpers.ResponseWithError(w, http.StatusInternalServerError, "Couldn't get user")
		return
	}

	newToken, err := auth.MakeJWT(dbUser.ID, api.JWTSecret, time.Hour)
	if err != nil {
		log.Printf("error making token: %s", err)
		helpers.ResponseWithError(w, http.StatusInternalServerError, "Couldn't make JWT token")
		return
	}

	helpers.ResponseWithJSON(w, http.StatusOK, struct {
		Token string `json:"token"`
	}{
		Token: newToken,
	})

}

func (api *apiConfig) RevokeHandler(w http.ResponseWriter, r *http.Request) {
	refreshToken, err := auth.GetRefreshToken(r.Header)
	if err != nil {
		log.Printf("error getting refresh token: %v", err)
		helpers.ResponseWithError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	if err := api.DB.RevokeRefreshToken(r.Context(), refreshToken); err != nil {
		log.Printf("error revoking refresh token: %v", err)
		helpers.ResponseWithError(w, http.StatusInternalServerError, "Couldn't revoke refresh token")
		return
	}

	helpers.ResponseWithJSON(w, http.StatusNoContent, struct{}{})

}

// ------------------- Users --------------------------
type CreateUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
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

	hashed, err := auth.HashPassword(reqBody.Password)
	if err != nil {
		log.Printf("error hashing password: %s", err)
		helpers.ResponseWithError(w, http.StatusInternalServerError, "Couldn't hash password")
		return
	}
	reqBody.Password = hashed

	user, err := api.DB.CreateUser(r.Context(), database.CreateUserParams{
		Email:          reqBody.Email,
		HashedPassword: reqBody.Password,
	})
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

// ------------------- Chirps --------------------------
type CreateChirpRequest struct {
	Body string `json:"body"`
}

type ChirpResponse struct {
	Body      string    `json:"body"`
	UserId    string    `json:"user_id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	ID        uuid.UUID `json:"id"`
}

func (apiCfg *apiConfig) CreateChirpHandler(w http.ResponseWriter, r *http.Request) {

	bearerToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		log.Printf("error getting bearer token: %s", err)
		helpers.ResponseWithError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	userId, err := auth.ValidateJWT(bearerToken, apiCfg.JWTSecret)
	if err != nil {
		log.Printf("error validating token: %s", err)
		helpers.ResponseWithError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	decoder := json.NewDecoder(r.Body)
	req_body := CreateChirpRequest{}

	if err := decoder.Decode(&req_body); err != nil {
		log.Printf("error decoding request body: %s", err)
		helpers.ResponseWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	if len(req_body.Body) > 140 {
		helpers.ResponseWithError(w, http.StatusBadRequest, "Chirp is too long")
		return
	}

	cleaned := helpers.ReplaceProfanity(req_body.Body)

	chirp, err := apiCfg.DB.CreateChirp(r.Context(), database.CreateChirpParams{
		Body:   cleaned,
		UserID: userId,
	})
	if err != nil {
		log.Printf("error creating chirp: %s", err)
		helpers.ResponseWithError(w, http.StatusInternalServerError, "Couldn't create chirp")
		return
	}

	helpers.ResponseWithJSON(w, http.StatusCreated, ChirpResponse{
		Body:      chirp.Body,
		UserId:    userId.String(),
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
		ID:        chirp.ID,
	})

}

func (apiCfg *apiConfig) GetAllChirpsHandler(w http.ResponseWriter, r *http.Request) {
	chirps, err := apiCfg.DB.GetAllChirps(r.Context())
	if err != nil {
		log.Printf("error getting all chirps: %s", err)
		helpers.ResponseWithError(w, http.StatusInternalServerError, "Couldn't get chirps")
		return
	}
	response := []ChirpResponse{}
	for _, chirp := range chirps {
		response = append(response, ChirpResponse{
			ID:        chirp.ID,
			Body:      chirp.Body,
			UserId:    chirp.UserID.String(),
			CreatedAt: chirp.CreatedAt,
			UpdatedAt: chirp.UpdatedAt,
		})
	}

	helpers.ResponseWithJSON(w, http.StatusOK, response)

}

func (apiCfg *apiConfig) GetChirpByIdHandler(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("chirpId")

	chirp, err := apiCfg.DB.GetChirp(r.Context(), uuid.MustParse(idStr))
	if err == sql.ErrNoRows {
		helpers.ResponseWithError(w, http.StatusNotFound, "Chirp not found")
		return
	} else if err != nil {
		log.Printf("error getting chirp: %s", err)
		helpers.ResponseWithError(w, http.StatusInternalServerError, "Couldn't get chirp")
		return
	}
	helpers.ResponseWithJSON(w, http.StatusOK, ChirpResponse{
		ID:        chirp.ID,
		Body:      chirp.Body,
		UserId:    chirp.UserID.String(),
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
	})

}

func main() {
	godotenv.Load()

	tokenSecret := os.Getenv("JWT_SECRET")

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
		JWTSecret:      tokenSecret,
	}

	var server http.Server
	server.Handler = mux
	server.Addr = ":8080"

	mux.Handle("/app/", apiCfg.middlewareMetricInc((http.StripPrefix("/app", http.FileServer(http.Dir("./"))))))
	mux.HandleFunc("GET /admin/metrics", apiCfg.HandlerMetrics)
	mux.HandleFunc("POST /admin/reset", apiCfg.HandlerResetUsers)
	mux.HandleFunc("GET /api/healthz", handlers.HandlerReady)

	mux.HandleFunc("POST /api/chirps", apiCfg.CreateChirpHandler)
	mux.HandleFunc("GET /api/chirps", apiCfg.GetAllChirpsHandler)
	mux.HandleFunc("GET /api/chirps/{chirpId}", apiCfg.GetChirpByIdHandler)

	mux.HandleFunc("POST /api/users", apiCfg.CreateUserHandler)

	mux.HandleFunc("POST /api/login", apiCfg.LoginHandler)
	mux.HandleFunc("POST /api/refresh", apiCfg.RefreshHandler)
	mux.HandleFunc("POST /api/revoke", apiCfg.RevokeHandler)

	server.ListenAndServe()

}
