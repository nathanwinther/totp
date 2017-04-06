package totp

import (
  "bytes"
  "crypto/hmac"
  "crypto/rand"
  "crypto/sha1"
  "encoding/base32"
  "encoding/binary"
  "errors"
  "fmt"
  "strings"
  "time"
)

func CreateSecret(size int) (string, error) {
  if size < 16 || size > 128 {
    errors.New("Key size must be between 16 and 128")
  }

  random := make([]byte, size)
  _, err := rand.Read(random)
  if err != nil {
    return "", err
  }

  secret := base32.StdEncoding.EncodeToString(random)

  return secret[0:size], nil
}

func GetCode(secret string) (string, error) {
  return getCode(secret, time.Now().Unix() / 30)
}

func VerifyCode(secret string, code string, drift int) bool {
  timeSlice := time.Now().Unix() / 30

  for i := (drift * -1); i <= drift; i++ {
    calc, err := getCode(secret, timeSlice + int64(i))
    if err != nil {
      return false
    }
    if (timingSafeEquals(calc, code)) {
      return true
    }
  }

  return false
}

func getCode(secret string, timeSlice int64) (string, error) {
  key, err := base32.StdEncoding.DecodeString(secret)
  if err != nil {
    return "", err
  }

  value := new(bytes.Buffer)
  binary.Write(value, binary.BigEndian, uint64(timeSlice))

  h := hmac.New(sha1.New, key)
  h.Write(value.Bytes())

  hash := h.Sum(nil)

  offset := hash[len(hash)-1] & 0x0F
  hashpart := hash[offset:offset+4]

  number := binary.BigEndian.Uint32(hashpart) & 0x7FFFFFFF

  code := fmt.Sprintf("%d", number % 1000000)
  code = strings.Repeat("0", 6 - len(code)) + code

  return code, nil
}

func timingSafeEquals(a string, b string) bool {
  if len(a) != len(b) {
    return false
  }

  var result byte

  for i := 0; i < len(a); i++ {
    result |= a[i] ^ b[i]
  }

  return result == 0
}

