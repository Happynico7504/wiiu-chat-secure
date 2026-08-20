package database

func ValidateSessionToken(token string) bool {
	var count int
	err := Postgres.QueryRow(
		`SELECT COUNT(*) FROM nex_sessions WHERE token = $1 AND expires_at > NOW()`,
		token,
	).Scan(&count)
	return err == nil && count > 0
}

func SetSessionPID(token string, pid uint32) {
	Postgres.Exec(`UPDATE nex_sessions SET pid = $1 WHERE token = $2`, pid, token)
}
