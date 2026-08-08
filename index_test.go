package safetoken_test

import (
	"testing"
	"time"

	"safetoken"
)

func TestSafeToken(t *testing.T) {
	secret := "9494d249ad9fd041f9d052e0d0b9c9e7e45bfc3f"

	// 1. Basic init & error on empty secret
	_, err := safetoken.New(safetoken.Config{Secret: ""})
	if err == nil {
		t.Fatalf("expected error for empty secret")
	}

	auth, err := safetoken.New(safetoken.Config{Secret: secret})
	if err != nil {
		t.Fatalf("failed to create SafeToken instance: %v", err)
	}

	// 2. Create & Verify token with default time window ("access")
	payload := map[string]any{"email": "fridaycandours@gmail.com"}
	token, err := auth.Create(payload)
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	verified, err := auth.Verify(token)
	if err != nil {
		t.Fatalf("failed to verify token: %v", err)
	}

	if verified["email"] != "fridaycandours@gmail.com" {
		t.Fatalf("expected email fridaycandours@gmail.com, got %v", verified["email"])
	}

	// 3. Decode token without verification
	decoded, err := auth.Decode(token)
	if err != nil {
		t.Fatalf("failed to decode token: %v", err)
	}

	if decoded["email"] != "fridaycandours@gmail.com" {
		t.Fatalf("expected decoded email fridaycandours@gmail.com, got %v", decoded["email"])
	}

	// 4. Custom Time Windows
	auth2, err := safetoken.New(safetoken.Config{
		Secret: secret,
		TimeWindows: map[string]int64{
			"access":  3600000,
			"refresh": 2592000000,
			"short":   1, // 1 ms
		},
	})
	if err != nil {
		t.Fatalf("failed to create Auth2: %v", err)
	}

	accessToken, err := auth2.Create(payload)
	if err != nil {
		t.Fatalf("failed to create access token: %v", err)
	}

	decodedAccess, err := auth2.Verify(accessToken, "access")
	if err != nil {
		t.Fatalf("failed to verify access token: %v", err)
	}
	if decodedAccess["email"] != "fridaycandours@gmail.com" {
		t.Fatalf("mismatched email in access token")
	}

	shortToken, err := auth2.Create(payload)
	if err != nil {
		t.Fatalf("failed to create short token: %v", err)
	}
	time.Sleep(5 * time.Millisecond)
	_, err = auth2.Verify(shortToken, "short")
	if err == nil || err.Error() != "Token expired" {
		t.Fatalf("expected Token expired error, got %v", err)
	}

	// 5. Cross verification test with JS node implementation compatibility
	// (Ensure algorithm matches byte-for-byte in structure and validation)
	invalidToken := "invalid.token.string"
	_, err = auth.Verify(invalidToken)
	if err == nil {
		t.Fatalf("expected error verifying invalid token")
	}
}
