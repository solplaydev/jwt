package jwt

import (
	"context"
	"net/http"
)

// HttpMiddleware is a function that returns a new instance of the JWT middleware
func HttpMiddleware(jwtInteractor *Interactor, isRequired bool, scopes ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get the token from the request
			tokenStr, err := GetTokenFromRequest(r)
			if err != nil && isRequired {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			} else if err != nil && !isRequired {
				next.ServeHTTP(w, r)
				return
			}

			// Parse the token
			claims, err := jwtInteractor.ParseWithClaims(tokenStr)
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
