package redissession

import "errors"

var (
	ErrSessionNotFound = errors.New("session not found")

	ErrStoreNotFound = errors.New("store not found")

	ErrInvalidSessionData = errors.New("invalid session data")

	ErrEncryptionFailed = errors.New("encryption/decryption failed")

	ErrSignatureInvalid = errors.New("signature verification failed")

	ErrSessionExpired = errors.New("session expired")

	ErrInvalidConfiguration = errors.New("invalid configuration")
)
