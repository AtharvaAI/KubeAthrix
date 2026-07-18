package postgres

import "testing"

func TestIdempotencyAdvisoryLockKeyIsPostgresTextSafe(t *testing.T) {
	key := idempotencyAdvisoryLockKey("Insecure development administrator (insecure-development-user)", "stable-request-key")
	if key == "" {
		t.Fatal("expected lock key")
	}
	for _, char := range key {
		if char == 0 {
			t.Fatal("lock key must not contain a NUL byte because PostgreSQL text rejects it")
		}
	}
}
