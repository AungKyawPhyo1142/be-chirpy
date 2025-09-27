-- name: CreateChirp :one
INSERT INTO chirps (body, user_id) VALUES ($1, $2) RETURNING *;

-- name: GetAllChirps :many
SELECT * FROM chirps
ORDER BY created_at ASC;

-- name: GetChirp :one
SELECT * FROM chirps
WHERE id = $1;