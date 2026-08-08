package safetoken

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type SafeToken struct {
	timeWindow map[string]int64
	secret     string
}

type Config struct {
	TimeWindows map[string]int64
	Secret      string
}

func New(init Config) (*SafeToken, error) {
	if init.Secret == "" {
		return nil, errors.New("Please provide safetoken secret")
	}

	timeWindow := make(map[string]int64)
	if init.TimeWindows != nil {
		for k, v := range init.TimeWindows {
			timeWindow[k] = v
		}
	}
	if len(timeWindow) == 0 {
		timeWindow["access"] = 3600000 // 1 hour default (in ms)
	}

	return &SafeToken{
		timeWindow: timeWindow,
		secret:     init.Secret,
	}, nil
}

func (s *SafeToken) Create(data map[string]any) (string, error) {
	if data == nil {
		data = make(map[string]any)
	}
	return createHmacSha256Signature(data, s.secret, timestamp())
}

func (s *SafeToken) Verify(token string, timeWindowKeys ...string) (map[string]any, error) {
	timeWindowKey := "access"
	if len(timeWindowKeys) > 0 && timeWindowKeys[0] != "" {
		timeWindowKey = timeWindowKeys[0]
	}

	window, ok := s.timeWindow[timeWindowKey]
	if !ok {
		return nil, errors.New("Invalid time window")
	}

	return verifyToken(token, s.secret, window)
}

func (s *SafeToken) Decode(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 3 || parts[2] == "" {
		return nil, errors.New("Invalid token")
	}

	decodedData, err := base64UrlDecode(parts[2])
	if err != nil {
		return nil, errors.New("Invalid token")
	}

	var payload map[string]any
	if err := json.Unmarshal(decodedData, &payload); err != nil {
		return nil, errors.New("Invalid token")
	}

	return payload, nil
}

func createHmacSha256Signature(payload map[string]any, secret string, t string) (string, error) {
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	tbuf := base64UrlEncode([]byte(t))
	dataToSign := base64UrlEncode(payloadBytes)

	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(dataToSign + tbuf))
	signatureBuffer := h.Sum(nil)

	signature := base64UrlEncode(signatureBuffer)
	return fmt.Sprintf("%s.%s.%s", t, signature, dataToSign), nil
}

func verifyToken(token string, secret string, timeWindow int64) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("Invalid token")
	}

	t := parts[0]
	signature := parts[1]
	data := parts[2]

	if t == "" || signature == "" || data == "" {
		return nil, errors.New("Invalid token")
	}

	inTime, err := isIntime(timeWindow, t)
	if err != nil {
		return nil, err
	}
	if !inTime {
		return nil, errors.New("Token expired")
	}

	timeBase64 := base64UrlEncode([]byte(t))
	dataToSign := data + timeBase64

	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(dataToSign))
	signatureBuffer := h.Sum(nil)

	expectedSignature := base64UrlEncode(signatureBuffer)

	if timingSafeEqual(signature, expectedSignature) {
		decodedData, err := base64UrlDecode(data)
		if err != nil {
			return nil, errors.New("Invalid token")
		}
		var payload map[string]any
		if err := json.Unmarshal(decodedData, &payload); err != nil {
			return nil, errors.New("Invalid token")
		}
		return payload, nil
	}

	return nil, errors.New("Invalid token")
}

func isIntime(timeWindow int64, lastTime string) (bool, error) {
	if timeWindow <= 0 {
		return false, errors.New("Invalid time window")
	}
	lastTimeParsed, err := strconv.ParseInt(lastTime, 16, 64)
	if err != nil {
		return false, nil
	}

	nowMs := time.Now().UnixMilli()
	tokenMs := lastTimeParsed * 1000

	// Protect against future-dated token attack (allow up to 5s clock skew)
	diff := nowMs - tokenMs
	if diff < -5000 {
		return false, nil
	}

	return diff <= timeWindow, nil
}

func timestamp() string {
	t := uint32(time.Now().Unix())
	buffer := make([]byte, 4)
	binary.BigEndian.PutUint32(buffer, t)
	return hex.EncodeToString(buffer)
}

func timingSafeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func base64UrlEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func base64UrlDecode(str string) ([]byte, error) {
	data, err := base64.RawURLEncoding.DecodeString(str)
	if err != nil {
		s := strings.ReplaceAll(str, "-", "+")
		s = strings.ReplaceAll(s, "_", "/")
		for len(s)%4 != 0 {
			s += "="
		}
		return base64.StdEncoding.DecodeString(s)
	}
	return data, nil
}
