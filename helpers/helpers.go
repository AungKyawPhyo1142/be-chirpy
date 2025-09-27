package helpers

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

type ErrorResponse struct {
	Error string `json:"error"`
}

type Response struct {
	CleanedBody string `json:"cleaned_body"`
}

func ResponseWithError(w http.ResponseWriter, code int, msg string) {
	resp := ErrorResponse{
		Error: msg,
	}
	ResponseWithJSON(w, code, resp)

}

func ResponseWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	response, err := json.Marshal(payload)
	if err != nil {
		log.Printf("error parsing json: %s", err)
		return
	}
	w.Write(response)
}

func ReplaceProfanity(body string) string {
	profanity_words := []string{"kerfuffle", "sharbert", "fornax"}
	words := strings.Fields(body)
	for i, word := range words {
		for _, profanity := range profanity_words {
			if strings.ToLower(word) == profanity {
				words[i] = "****"
			}
		}
	}
	return strings.Join(words, " ")
}
