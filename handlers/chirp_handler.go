package handlers

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/AungKyawPhyo1142/chirpy/helpers"
)

type ValidateBody struct {
	Body string `json:"body"`
}

func HandlerValidateChirp(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "application/json")
	decoder := json.NewDecoder(r.Body)
	body := ValidateBody{}

	if err := decoder.Decode(&body); err != nil {
		log.Printf("error decoding request body: %s", err)
		helpers.ResponseWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	if len(body.Body) > 140 {
		helpers.ResponseWithError(w, http.StatusBadRequest, "Chirp is too long")
		return
	}

	cleaned := helpers.ReplaceProfanity(body.Body)

	response := helpers.Response{
		CleanedBody: cleaned,
	}

	helpers.ResponseWithJSON(w, http.StatusOK, response)

}
