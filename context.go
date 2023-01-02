package jwt

import (
	"context"
	"fmt"
)

type (
	// ContextKey is a struct that contains the key that is used to set the value in the context
	ContextKey struct{ Key string }
)

// String is a method that returns the key as a string
func (c ContextKey) String() string {
	if c.Key == "" {
		return fmt.Sprintf("%#v", c)
	}

	return c.Key
}

// Predefined context keys
var (
	ClaimsKey = ContextKey{Key: "claims"}
	TokenKey  = ContextKey{Key: "token"}
)

// GetClaimsFromContext is a function that returns the claims from the context
// and casts them to the Claims type, if possible
func GetClaimsFromContext(ctx context.Context) (Claims, error) {
	claims, ok := ctx.Value(ClaimsKey).(Claims)
	if !ok {
		return Claims{}, ErrInvalidClaims
	}

	return claims, nil
}

// GetUserIDFromContext is a function that returns the user ID from the context
func GetUserIDFromContext(ctx context.Context) (string, error) {
	claims, err := GetClaimsFromContext(ctx)
	if err != nil {
		return "", err
	}

	return claims.UserID, nil
}

// GetSessionIDFromContext is a function that returns the session ID from the context
func GetSessionIDFromContext(ctx context.Context) (string, error) {
	claims, err := GetClaimsFromContext(ctx)
	if err != nil {
		return "", err
	}

	return claims.Id, nil
}

// GetTokenFromContext is a function that returns the token from the context
func GetTokenFromContext(ctx context.Context) (string, error) {
	token, ok := ctx.Value(TokenKey).(string)
	if !ok {
		return "", ErrInvalidToken
	}

	return token, nil
}

// GetClientIDFromContext is a function that returns the client ID from the context
func GetClientIDFromContext(ctx context.Context) (string, error) {
	claims, err := GetClaimsFromContext(ctx)
	if err != nil {
		return "", err
	}

	return claims.ClientID, nil
}

// GetScopeFromContext is a function that returns the scope from the context
func GetScopeFromContext(ctx context.Context) (string, error) {
	claims, err := GetClaimsFromContext(ctx)
	if err != nil {
		return "", err
	}

	return claims.Scope, nil
}
