package jwt

import (
	"context"
	"encoding/base64"
	"strings"

	"github.com/go-oauth2/oauth2/v4"
	"github.com/google/uuid"
)

type (
	// JWTAccessGenerate is a struct that contains the methods that are used to generate a JWT token
	// for the access token
	JWTAccessGenerate struct {
		jwt       jwtInteractor
		pidCtxKey ContextKey
	}

	// jwtInteractor is an interface that contains the methods that are used to interact with the JWT
	jwtInteractor interface {
		GenerateToken(claims Claims) (string, error)
	}
)

// NewJWTAccessGenerate is a function that returns a new instance of the JWT access token generator
func NewJWTAccessGenerate(jwtInteractor jwtInteractor, pidCtxKey ContextKey) *JWTAccessGenerate {
	return &JWTAccessGenerate{
		jwt:       jwtInteractor,
		pidCtxKey: pidCtxKey,
	}
}

// Token is a method that generates a new JWT token
// Implements the oauth2.AccessGenerate interface from the go-oauth2/oauth2 package
func (a *JWTAccessGenerate) Token(ctx context.Context, data *oauth2.GenerateBasic, isGenRefresh bool) (string, string, error) {
	pid, _ := GetProjectIDFromContext(ctx, a.pidCtxKey)

	claims := NewClaims(
		WithClientID(data.Client.GetID()),
		WithUserID(data.UserID),
		WithScope(data.TokenInfo.GetScope()),
		WithProjectID(pid),
		WithExpiresAt(data.TokenInfo.GetAccessCreateAt().Add(data.TokenInfo.GetAccessExpiresIn()).Unix()),
	)

	access, err := a.jwt.GenerateToken(claims)
	if err != nil {
		return "", "", err
	}

	var refresh string
	if isGenRefresh {
		t := uuid.NewSHA1(uuid.Must(uuid.NewRandom()), []byte(access)).String()
		refresh = base64.URLEncoding.EncodeToString([]byte(t))
		refresh = strings.ToUpper(strings.TrimRight(refresh, "="))
	}

	return access, refresh, nil
}
