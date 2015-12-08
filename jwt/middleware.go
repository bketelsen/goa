package jwt

import (
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/raphael/goa"
)

const ()

// Middleware returns a goa middleware which implements the given CORS specification.
func Middleware(spec Specification) goa.Middleware {
	return func(h goa.Handler) goa.Handler {
		return func(ctx *goa.Context) error {
			return nil
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
