package jwt_test

import (
	"testing"
	"time"

	"github.com/solplaydev/jwt"
	"github.com/stretchr/testify/require"
)

func TestInteractor(t *testing.T) {
	i := jwt.NewInteractor([]byte("secret"), time.Hour)
	var tokenStr string

	t.Run("should generate a token", func(t *testing.T) {
		var err error
		tokenStr, err = i.GenerateToken(jwt.NewClaims(jwt.WithID("id"), jwt.WithExpiresAt(time.Now().Add(time.Hour).Unix())))
		require.NoError(t, err)
		require.NotEmpty(t, tokenStr)
	})

	t.Run("should parse a token", func(t *testing.T) {
		claims, err := i.ParseWithClaims(tokenStr)
		require.NoError(t, err)
		require.NotEmpty(t, claims)
		require.Equal(t, "id", claims.Id)
	})

	t.Run("should fail to parse a token: token malformed", func(t *testing.T) {
		claims, err := i.ParseWithClaims("invalid")
		require.Error(t, err)
		require.ErrorIs(t, err, jwt.ErrTokenMalformed)
		require.Empty(t, claims)
	})

	t.Run("should fail to parse a token: token expired", func(t *testing.T) {
		tokenStr, err := i.GenerateToken(jwt.NewClaims(jwt.WithID("id"), jwt.WithExpiresAt(time.Now().Add(-time.Hour).Unix())))
		require.NoError(t, err)
		require.NotEmpty(t, tokenStr)

		claims, err := i.ParseWithClaims(tokenStr)
		require.Error(t, err)
		require.ErrorIs(t, err, jwt.ErrTokenExpired)
		require.Empty(t, claims)
	})

	t.Run("should fail to parse a token: token inactive", func(t *testing.T) {
		tokenStr, err := i.GenerateToken(jwt.NewClaims(
			jwt.WithID("id"),
			jwt.WithNotBefore(time.Now().Add(time.Hour).Unix()),
		))
		require.NoError(t, err)
		require.NotEmpty(t, tokenStr)

		claims, err := i.ParseWithClaims(tokenStr)
		require.Error(t, err)
		require.ErrorIs(t, err, jwt.ErrTokenNotActive)
		require.Empty(t, claims)
	})

	t.Run("should fail to parse a token: invalid token", func(t *testing.T) {
		tokenStr, err := i.GenerateToken(jwt.NewClaims(jwt.WithID("id")))
		require.NoError(t, err)
		require.NotEmpty(t, tokenStr)

		i := jwt.NewInteractor([]byte("invalid"), 0)
		claims, err := i.ParseWithClaims(tokenStr)
		require.Error(t, err)
		require.ErrorIs(t, err, jwt.ErrInvalidToken)
		require.Empty(t, claims)
	})
}
