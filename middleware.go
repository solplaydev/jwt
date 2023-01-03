package jwt

import (
	"context"
	"net/http"

	"github.com/labstack/echo/v4"
)

type (
	Middleware struct {
		// Skipper defines a function to skip middleware.
		skipper Skipper

		// Required defines if the middleware is required or not.
		isRequired bool

		// JWT Interactor
		jwt jwtInteractor
	}

	// Skipper defines a function to skip middleware.
	Skipper func(c context.Context) bool

	// jwtInteractor is an interface that wraps the ParseWithClaims method.
	jwtInteractor interface {
		ParseWithClaims(tokenStr string) (*Claims, error)
	}
)

// NewMiddleware returns a new instance of the JWT middleware.
func NewMiddleware(jwtInteractor jwtInteractor, isRequired bool, skipper Skipper) *Middleware {
	return &Middleware{
		skipper:    skipper,
		isRequired: isRequired,
		jwt:        jwtInteractor,
	}
}

// Default is a function that returns a new instance of the JWT middleware for net/http.
func (m *Middleware) Default(scopes ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if the middleware should be skipped
			if m.skipper != nil && m.skipper(r.Context()) {
				next.ServeHTTP(w, r)
				return
			}

			// Get the token from the request
			tokenStr, err := GetTokenFromRequest(r)
			if err != nil && m.isRequired {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			} else if err != nil && !m.isRequired {
				next.ServeHTTP(w, r)
				return
			}

			// Parse the token
			claims, err := m.jwt.ParseWithClaims(tokenStr)
			if err != nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Check if the token has the required scopes
			if len(scopes) > 0 {
				for _, scope := range scopes {
					if !claims.CheckScopeInAllowed(scope) {
						http.Error(w, "Forbidden", http.StatusForbidden)
						return
					}
				}
			}

			// Set the token in the context
			ctx := context.WithValue(r.Context(), TokenKey, tokenStr)
			// Set the claims in the context
			ctx = context.WithValue(ctx, ClaimsKey, claims)

			// Call the next handler
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Echo is a function that returns a new instance of the JWT middleware for Echo framework
func (m *Middleware) Echo(scopes ...string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Check if the middleware should be skipped
			if m.skipper != nil && m.skipper(c.Request().Context()) {
				return next(c)
			}

			// Get the token from the request
			tokenStr, err := GetTokenFromRequest(c.Request())
			if err != nil && m.isRequired {
				return echo.ErrUnauthorized.SetInternal(err)
			} else if err != nil && !m.isRequired {
				return next(c)
			}

			// Parse the token
			claims, err := m.jwt.ParseWithClaims(tokenStr)
			if err != nil {
				return echo.ErrUnauthorized.SetInternal(err)
			}

			// Check if the token has the required scopes
			if len(scopes) > 0 {
				for _, scope := range scopes {
					if !claims.CheckScopeInAllowed(scope) {
						return echo.ErrForbidden
					}
				}
			}

			// Set the token in the context
			c.Set(TokenKey.String(), tokenStr)
			// Set the claims in the context
			c.Set(ClaimsKey.String(), claims)

			// Call the next handler
			return next(c)
		}
	}
}
