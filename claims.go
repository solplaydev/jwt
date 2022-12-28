package jwt

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
)

// Predefined auth types for the claims
const (
	AuthTypeUser     = "u" // User auth (email/password)
	AuthTypeApp      = "a" // App auth (client id/secret)
	AuthTypeInternal = "i" // Internal auth, used for internal services. (client id/secret)
)

// Claims is a struct that contains the claims that are used in the JWT
type (
	Claims struct {
		// Standard claims
		jwt.StandardClaims
		// Custom claims
		UserID    string `json:"uid,omitempty"`
		ProjectID string `json:"pid,omitempty"`
		ClientID  string `json:"cid,omitempty"`
		Scope     string `json:"scope,omitempty"`
		AuthType  string `json:"auth,omitempty"`
	}

	// ClaimsOption is a function that is used to set the claims options
	ClaimsOption func(*Claims)

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

// ClaimsCtxKey is a variable that is used to set the claims in the context
var ClaimsKey = ContextKey{Key: "claims"}

// NewClaims is a function that returns a new instance of the claims
func NewClaims(opts ...ClaimsOption) Claims {
	c := Claims{
		StandardClaims: jwt.StandardClaims{
			Id:       uuid.New().String(),
			IssuedAt: time.Now().Unix(),
		},
	}

	for _, opt := range opts {
		opt(&c)
	}

	return c
}

// IsAppAuth is a method that returns true if the auth type is app
func (c Claims) IsAppAuth() bool {
	return c.AuthType == AuthTypeApp
}

// IsUserAuth is a method that returns true if the auth type is user
func (c Claims) IsUserAuth() bool {
	return c.AuthType == AuthTypeUser
}

// IsInternalAuth is a method that returns true if the auth type is internal
func (c Claims) IsInternalAuth() bool {
	return c.AuthType == AuthTypeInternal
}

// WithUserID is a function that sets the user id in the claims
func WithUserID(userID string) ClaimsOption {
	return func(c *Claims) {
		c.UserID = userID
	}
}

// WithProjectID is a function that sets the project id in the claims
func WithProjectID(projectID string) ClaimsOption {
	return func(c *Claims) {
		c.ProjectID = projectID
	}
}

// WithClientID is a function that sets the client id in the claims
func WithClientID(clientID string) ClaimsOption {
	return func(c *Claims) {
		c.ClientID = clientID
	}
}

// WithScope is a function that sets the scope in the claims
func WithScope(scope string) ClaimsOption {
	return func(c *Claims) {
		c.Scope = scope
	}
}

// WithAuthType is a function that sets the auth type in the claims
func WithAuthType(authType string) ClaimsOption {
	return func(c *Claims) {
		if authType == AuthTypeUser || authType == AuthTypeApp {
			c.AuthType = authType
		}
	}
}

// WithCustomAuthType is a function that sets the auth type in the claims
func WithCustomAuthType(authType string) ClaimsOption {
	return func(c *Claims) {
		c.AuthType = authType
	}
}

// WithExpiresAt is a function that sets the expires at in the claims
// Parameter expiresAt is the unix timestamp
func WithExpiresAt(expiresAt int64) ClaimsOption {
	return func(c *Claims) {
		c.ExpiresAt = expiresAt
	}
}

// WithTTL is a function that sets the expires at in the claims
// Parameter ttl is the time to live in seconds
func WithTTL(ttl int64) ClaimsOption {
	if ttl <= 0 {
		ttl = 3600 // 1 hour
	}

	return func(c *Claims) {
		if c.IssuedAt == 0 {
			c.IssuedAt = time.Now().Unix()
		}
		c.ExpiresAt = ttl + c.IssuedAt
	}
}

// WithID is a function that sets the id in the claims
func WithID(id string) ClaimsOption {
	return func(c *Claims) {
		c.Id = id
	}
}

// WithIssuer is a function that sets the issuer in the claims
func WithIssuer(issuer string) ClaimsOption {
	return func(c *Claims) {
		c.Issuer = issuer
	}
}

// WithSubject is a function that sets the subject in the claims
func WithSubject(subject string) ClaimsOption {
	return func(c *Claims) {
		c.Subject = subject
	}
}

// WithAudience is a function that sets the audience in the claims
func WithAudience(audience string) ClaimsOption {
	return func(c *Claims) {
		c.Audience = audience
	}
}

// WithNotBefore is a function that sets the not before in the claims
func WithNotBefore(notBefore int64) ClaimsOption {
	return func(c *Claims) {
		c.NotBefore = notBefore
	}
}

// WithIssuedAt is a function that sets the issued at in the claims
func WithIssuedAt(issuedAt int64) ClaimsOption {
	return func(c *Claims) {
		c.IssuedAt = issuedAt
	}
}
