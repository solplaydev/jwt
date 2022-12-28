package jwt

import (
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
)

type (
	// Interactor is a struct that contains the methods that are used to interact with the JWT
	Interactor struct {
		signingKey []byte
		ttl        time.Duration
	}
)

// NewInteractor is a function that returns a new instance of the JWT interactor
func NewInteractor(signingKey []byte, ttl time.Duration) *Interactor {
	if signingKey == nil {
		panic("signing key is not set")
	}

	if ttl == 0 {
		ttl = time.Hour
	}

	return &Interactor{
		signingKey: signingKey,
		ttl:        ttl,
	}
}

// GenerateToken is a method that generates a new JWT token
func (i *Interactor) GenerateToken(claims Claims) (string, error) {
	if claims.ExpiresAt == 0 {
		claims.ExpiresAt = time.Now().Add(i.ttl).Unix()
	}

	if claims.Id == "" {
		claims.Id = uuid.New().String()
	}

	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(i.signingKey)
	if err != nil {
		return "", ErrFailedToSignToken
	}

	return token, nil
}

// ParseWithClaims parses a JWT token and returns its claims.
func (i *Interactor) ParseWithClaims(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrUnexpectedSigningMethod
		}

		return i.signingKey, nil
	})
	if err != nil {
		if e, ok := err.(*jwt.ValidationError); ok {
			switch {
			case e.Errors&jwt.ValidationErrorMalformed != 0:
				return nil, ErrTokenMalformed
			case e.Errors&jwt.ValidationErrorExpired != 0:
				return nil, ErrTokenExpired
			case e.Errors&jwt.ValidationErrorSignatureInvalid != 0:
				return nil, ErrInvalidToken
			case e.Errors&jwt.ValidationErrorNotValidYet != 0:
				return nil, ErrTokenNotActive
			case e.Inner != nil:
				return nil, e.Inner
			}
		}
		return nil, ErrFailedToParseToken
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, ErrFailedToParseClaims
	}

	return claims, nil
}
