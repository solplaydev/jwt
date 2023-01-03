package jwt

import (
	"context"
	"fmt"

	"github.com/google/uuid"
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
	ClaimsKey    = ContextKey{Key: "claims"}
	TokenKey     = ContextKey{Key: "token"}
	ProjectIDKey = ContextKey{Key: "project_id"}
	AuthTypeKey  = ContextKey{Key: "auth_type"}
)

// GetClaimsFromContext is a function that returns the claims from the context
// and casts them to the Claims type, if possible
func GetClaimsFromContext(ctx context.Context) (*Claims, error) {
	claims, ok := ctx.Value(ClaimsKey).(*Claims)
	if !ok {
		// Try to get claims by string context key
		claims, ok = ctx.Value(ClaimsKey.String()).(*Claims)
		if !ok {
			return nil, ErrInvalidClaims
		}
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
		// Try to get claims by string context key
		token, ok = ctx.Value(TokenKey.String()).(string)
		if !ok {
			return "", ErrInvalidToken
		}
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

// GetProjectIDFromContext is a function that returns the project ID from the context
func GetProjectIDFromContext(ctx context.Context, pidCtxKey ContextKey) (string, error) {
	projectID := ctx.Value(pidCtxKey)
	if projectID == nil {
		// Try to get claims by string context key
		projectID = ctx.Value(pidCtxKey.String())
		if projectID == nil {
			return "", ErrInvalidProjectID
		}
	}

	if result, ok := projectID.(string); ok {
		return result, nil
	}

	if result, ok := projectID.(int); ok {
		return fmt.Sprintf("%d", result), nil
	}

	if result, ok := projectID.(uuid.UUID); ok {
		return result.String(), nil
	}

	return "", ErrInvalidProjectID
}

// GetAuthTypeFromContext is a function that returns the auth type from the context
func GetAuthTypeFromContext(ctx context.Context, authTypeCtxKey ContextKey) (string, error) {
	authType := ctx.Value(authTypeCtxKey)
	if authType == nil {
		// Try to get claims by string context key
		authType = ctx.Value(authTypeCtxKey.String())
		if authType == nil {
			return "", ErrInvalidAuthType
		}
	}

	result, ok := authType.(string)
	if !ok {
		return "", ErrInvalidAuthType
	}

	switch result {
	case AuthTypeUser, AuthTypeApp, AuthTypeInternal:
		return result, nil
	}

	return "", ErrInvalidAuthType
}
