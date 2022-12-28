package jwt

import "github.com/labstack/echo/v4"

// EchoMiddleware is a function that returns a new instance of the JWT middleware
func EchoMiddleware(jwtInteractor *Interactor, isRequired bool) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Get the token from the request
			tokenStr := c.Request().Header.Get("Authorization")
			if tokenStr == "" {
				if isRequired {
					return echo.ErrUnauthorized.SetInternal(ErrInvalidToken)
				}

				return next(c)
			}

			// Parse the token
			claims, err := jwtInteractor.ParseWithClaims(tokenStr)
			if err != nil {
				return echo.ErrUnauthorized.SetInternal(err)
			}

			// Set the claims in the context
			c.Set(ClaimsKey.String(), claims)
			return next(c)
		}
	}
}
