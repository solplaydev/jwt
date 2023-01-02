package jwt

import (
	"net/http"

	"github.com/pkg/errors"
)

// Predefined package errors.
var (
	ErrInvalidToken            = errors.New("invalid_token")
	ErrTokenMalformed          = errors.New("token_malformed")
	ErrTokenExpired            = errors.New("token_expired")
	ErrTokenNotActive          = errors.New("token_inactive")
	ErrInvalidSession          = errors.New("invalid_session")
	ErrFailedToParseClaims     = errors.New("failed_parse_claims")
	ErrUnexpectedSigningMethod = errors.New("unexpected_signing_method")
	ErrFailedToSignToken       = errors.New("failed_to_sign_token")
	ErrFailedToParseToken      = errors.New("failed_to_parse_token")
	ErrInvalidClaims           = errors.New("invalid_claims")
	ErrInvalidProjectID        = errors.New("invalid_project_id")
)

// Error codes.
var ErrorHTTPCodes = map[error]int{
	ErrInvalidToken:            http.StatusUnauthorized,
	ErrTokenMalformed:          http.StatusBadRequest,
	ErrTokenExpired:            http.StatusUnauthorized,
	ErrTokenNotActive:          http.StatusUnauthorized,
	ErrInvalidSession:          http.StatusUnauthorized,
	ErrFailedToParseClaims:     http.StatusBadRequest,
	ErrUnexpectedSigningMethod: http.StatusBadRequest,
	ErrFailedToSignToken:       http.StatusInternalServerError,
	ErrFailedToParseToken:      http.StatusBadRequest,
	ErrInvalidClaims:           http.StatusBadRequest,
	ErrInvalidProjectID:        http.StatusBadRequest,
}

// Error messages.
var ErrorMessages = map[error]string{
	ErrInvalidToken:            "Invalid token",
	ErrTokenMalformed:          "Malformed token",
	ErrTokenExpired:            "Token expired",
	ErrTokenNotActive:          "Token not active",
	ErrInvalidSession:          "Invalid session",
	ErrFailedToParseClaims:     "Failed to parse claims",
	ErrUnexpectedSigningMethod: "Unexpected signing method",
	ErrFailedToSignToken:       "Failed to sign token",
	ErrFailedToParseToken:      "Failed to parse token",
	ErrInvalidClaims:           "Invalid claims",
	ErrInvalidProjectID:        "Invalid project ID",
}

// Error is a custom error type.
type Error struct {
	Err  error  `json:"error,omitempty"`         // Original error.
	Code int    `json:"error_code,omitempty"`    // HTTP status code.
	Msg  string `json:"error_message,omitempty"` // Error message.
}

// NewError creates a new Error.
func NewError(err error) *Error {
	return &Error{
		Err:  err,
		Code: ErrorHTTPCodes[err],
		Msg:  ErrorMessages[err],
	}
}

// Error returns the error message.
func (e *Error) Error() string {
	return e.Msg
}

// Unwrap returns the original error.
func (e *Error) Unwrap() error {
	return e.Err
}

// Is checks if the error is of the given type.
func (e *Error) Is(err error) bool {
	return errors.Is(e.Err, err)
}

// As checks if the error can be converted to the given type.
func (e *Error) As(err any) bool {
	return errors.As(e.Err, err)
}
