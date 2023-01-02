package jwt

import (
	"context"
	"net/http"
)

// HttpMiddleware is a function that returns a new instance of the JWT middleware
func HttpMiddleware(jwtInteractor *Interactor, isRequired bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get the token from the request
			tokenStr := r.Header.Get("Authorization")
			if tokenStr == "" {
				if isRequired {
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}

				next.ServeHTTP(w, r)
				return
			}

			// Remove the "Bearer " prefix
			if len(tokenStr) > 7 && tokenStr[:7] == "Bearer " {
				tokenStr = tokenStr[7:]
			}

			// Parse the token
			claims, err := jwtInteractor.ParseWithClaims(tokenStr)
			if err != nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Set the token in the context
			ctx := context.WithValue(r.Context(), TokenKey, tokenStr)
			// Set the claims in the context
			ctx = context.WithValue(ctx, ClaimsKey, claims)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
