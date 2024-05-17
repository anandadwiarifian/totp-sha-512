package main

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base32"
	"fmt"
	"math"
	"time"
)

func main() {
	fmt.Println("enter your secret:")
	var secret string
	fmt.Scanln(&secret)
	fmt.Println("TOTP:", generateTOTP(secret, 10))
}

func generateTOTP(secret string, digit int) string {
	key := base32.StdEncoding.EncodeToString([]byte(secret))
	// Ensure the key is uppercase since Base32 encoding requires it
	// var epochSeconds int64 = 1715921191
	epochSeconds := time.Now().Unix()
	timeStep := 30
	T := epochSeconds / int64(timeStep)
	return hotp(key, T, digit)
}

func hotp(secret string, counter int64, digits int) string {
	key, _ := base32.StdEncoding.DecodeString(secret)
	buf := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		buf[i] = byte(counter)
		counter >>= 8
	}

	hmacSha := hmac.New(sha512.New, key)
	hmacSha.Write(buf)
	hash := hmacSha.Sum(nil)
	offset := hash[len(hash)-1] & 0x0F
	binary := (int(hash[offset])&0x7F)<<24 |
		(int(hash[offset+1])&0xFF)<<16 |
		(int(hash[offset+2])&0xFF)<<8 |
		(int(hash[offset+3]) & 0xFF)

	otp := binary % int(math.Pow10(digits))
	return fmt.Sprintf(fmt.Sprintf("%%0%dd", digits), otp)
}
