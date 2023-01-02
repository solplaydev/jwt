package jwt

import "net/http"

// GetTokenFromRequest is a function that returns the token string from the request (header or query parameter)
func GetTokenFromRequest(r *http.Request) (string, error) {
	// Get the token from the request
	tokenStr := r.Header.Get("Authorization")
	if tokenStr == "" && r.URL != nil {
		tokenStr = r.URL.Query().Get("token")
	}

	// Check if the token is empty, if so return an error
	if tokenStr == "" {
		return "", ErrInvalidToken
	}

	// Remove the "Bearer " prefix
	if len(tokenStr) > 7 && tokenStr[:7] == "Bearer " {
		tokenStr = tokenStr[7:]
	}

	return tokenStr, nil
}
