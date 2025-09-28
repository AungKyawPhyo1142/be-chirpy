package tests

import (
	"testing"
	"time"

	"github.com/AungKyawPhyo1142/chirpy/internal/auth"
	"github.com/google/uuid"
)

func TestJWTLifecycle(t *testing.T) {
	secret := "test-secret"
	userID := uuid.New()

	t.Run("valid token", func(t *testing.T) {
		// Create token
		token, err := auth.MakeJWT(userID, secret, time.Minute)
		if err != nil {
			t.Fatalf("unexpected error creating JWT: %v", err)
		}

		// Validate token
		gotID, err := auth.ValidateJWT(token, secret)
		if err != nil {
			t.Fatalf("unexpected error validating JWT: %v", err)
		}

		if gotID != userID {
			t.Errorf("expected userID %v, got %v", userID, gotID)
		}
	})

	t.Run("expired token", func(t *testing.T) {
		token, err := auth.MakeJWT(userID, secret, -time.Minute) // already expired
		if err != nil {
			t.Fatalf("unexpected error creating JWT: %v", err)
		}

		_, err = auth.ValidateJWT(token, secret)
		if err == nil {
			t.Error("expected error for expired token, got nil")
		}
	})

	t.Run("wrong secret", func(t *testing.T) {
		token, err := auth.MakeJWT(userID, secret, time.Minute)
		if err != nil {
			t.Fatalf("unexpected error creating JWT: %v", err)
		}

		_, err = auth.ValidateJWT(token, "wrong-secret")
		if err == nil {
			t.Error("expected error for wrong secret, got nil")
		}
	})
}
