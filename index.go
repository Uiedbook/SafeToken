package safetoken

import (
	"crypto/hmac"
	"crypto/subtle"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
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

	timeWindow := init.TimeWindows
	if timeWindow == nil {
		timeWindow = map[string]int64{
			"access": 3600000, // 1 hour default
		}
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
	if err := json.Unmarshal([]byte(decodedData), &payload); err != nil {
		return nil, errors.New("Invalid token")
	}

	return payload, nil
}

func createHmacSha256Signature(payload map[string]any, secret string, t string) (string, error) {
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	tbuf := base64UrlEncode(t)
	dataToSign := base64UrlEncode(string(payloadBytes))

	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(dataToSign + tbuf))
	signatureBuffer := h.Sum(nil)

	signature := base64UrlEncode(string(signatureBuffer))
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

	timeBase64 := base64UrlEncode(t)
	dataToSign := data + timeBase64

	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(dataToSign))
	signatureBuffer := h.Sum(nil)

	expectedSignature := base64UrlEncode(string(signatureBuffer))

	if timingSafeEqual(signature, expectedSignature) {
		decodedData, err := base64UrlDecode(data)
		if err != nil {
			return nil, errors.New("Invalid token")
		}
		var payload map[string]any
		if err := json.Unmarshal([]byte(decodedData), &payload); err != nil {
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
	ms := int64(math.Abs(float64(time.Now().UnixMilli() - lastTimeParsed*1000)))
	return timeWindow > ms, nil
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

func base64UrlEncode(str string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(str))
}

func base64UrlDecode(str string) (string, error) {
	data, err := base64.RawURLEncoding.DecodeString(str)
	if err != nil {
		// Fallback to std encoding with standard replace if needed
		s := strings.ReplaceAll(str, "-", "+")
		s = strings.ReplaceAll(s, "_", "/")
		for len(s)%4 != 0 {
			s += "="
		}
		data, err = base64.StdEncoding.DecodeString(s)
		if err != nil {
			return "", err
		}
	}
	return string(data), nil
}
