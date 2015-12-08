package jwt

import (
	"net/http"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/raphael/goa"
)

// JWTKey is the JWT middleware key used to store the token in the context.
const JWTKey middlewareKey = 0

// middlewareKey is the private type used for goa middlewares to store values in the context.
// It is private to avoid possible collisions with keys used by other packages.
type middlewareKey int

// JWTHeader is the name of the header used to transmit the JWT token.
const JWTHeader = "Authorization"

type Specification struct {
	// TokenHeader is the HTTP header to search for the JWT Token
	// Defaults to "Authorization"
	TokenHeader string
	// TokenParam is the request parameter to parse for the JWT Token
	// Defaults to "token"
	TokenParam string
	// AllowParam is a flag that determines whether it is allowable
	// to parse tokens from the querystring
	// Defaults to false
	AllowParam bool
	// ValidationFunc is a function that returns the key to validate the JWT
	// See github.com/dgrijalva/jwt for specification
	// Required, no default
	ValidationFunc jwt.Keyfunc
	// AuthOptions is a flag that determines whether a token is required on OPTIONS
	// requests
	AuthOptions bool
}

// JWTMiddleware is a middleware that injects retrieves a JWT token from the request if present and
// injects it into the context.  It checks for the token in the HTTP Headers first, then the querystring if
// the specification "AllowParam" is true.
// Retrieve it using ctx.Value(JWTKey).
func JWTMiddleware(spec Specification) goa.Middleware {
	return func(h goa.Handler) goa.Handler {
		return func(ctx *goa.Context) error {

			// If AuthOptions is false, and this is an OPTIONS request
			// just let the request fly
			if !spec.AuthOptions && ctx.Request().Method == "OPTIONS" {
				return h(ctx)
			}

			if spec.TokenHeader == "" {
				spec.TokenHeader = "Authorization"
			}
			if spec.TokenParam == "" {
				spec.TokenParam = "token"
			}
			var found bool
			var token string
			header := ctx.Request().Header.Get(spec.TokenHeader)

			if header != "" {
				parts := strings.Split(header, " ")
				if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
					// This is an error
				}
				token = parts[1]
				found = true
			}
			if !found && spec.AllowParam {
				token = ctx.Request().URL.Query().Get(spec.TokenParam)
			}

			if token == "" {
				err := ctx.Respond(http.StatusUnauthorized, []byte(http.StatusText(http.StatusUnauthorized)))
				return err
			}

			ctx.SetValue(JWTKey, token)

			return h(ctx)
		}
	}
}

func Token(claims map[string]string) (string, error) {
	// create a signer for rsa 256
	t := jwt.New(jwt.GetSigningMethod("RS256"))

	// set our claims
	t.Claims["AccessToken"] = "level1"

	// set the expire time
	// see http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-20#section-4.1.4
	t.Claims["exp"] = time.Now().Add(time.Minute * 1).Unix()
	return t.SignedString("blah")

}
