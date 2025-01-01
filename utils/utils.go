package utils

import (
	"golang.org/x/crypto/bcrypt"
)

func CreateHashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 10) // 10 -> 2^10 hashes slows hashing more secure

	return string(bytes), err
}
