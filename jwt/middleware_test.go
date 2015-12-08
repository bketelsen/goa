package jwt_test

import (
	"net/http"
	"strings"

	"gopkg.in/inconshreveable/log15.v2"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/raphael/goa"
	"github.com/raphael/goa/jwt"
)

var _ = Describe("JWT Middleware", func() {
	var handler *testHandler
	var ctx *goa.Context
	var spec jwt.Specification
	var req *http.Request
	var err error
	params := map[string]string{"param": "value"}
	query := map[string][]string{"query": []string{"qvalue"}}
	payload := map[string]interface{}{"payload": 42}

	BeforeEach(func() {
		req, err = http.NewRequest("POST", "/goo", strings.NewReader(`{"payload":42}`))
		Ω(err).ShouldNot(HaveOccurred())
		rw := new(TestResponseWriter)
		ctx = goa.NewContext(nil, req, rw, params, query, payload)
		handler = new(testHandler)
		logger := log15.New("test", "test")
		logger.SetHandler(handler)
		ctx.Logger = logger
		spec = jwt.Specification{
			AllowParam: true,
		}
	})

	It("requires a jwt token be present", func() {
		h := func(ctx *goa.Context) error {
			ctx.JSON(200, "ok")
			return nil
		}
		jw := jwt.JWTMiddleware(spec)(h)
		Ω(jw(ctx)).ShouldNot(HaveOccurred())
		Ω(ctx.ResponseStatus()).Should(Equal(http.StatusUnauthorized))

	})

	It("returns the jwt token that was sent", func() {
		req.Header.Set("Authorization", "bearer TOKEN")
		h := func(ctx *goa.Context) error {
			ctx.JSON(200, "ok")
			return nil
		}
		jw := jwt.JWTMiddleware(spec)(h)
		Ω(jw(ctx)).ShouldNot(HaveOccurred())
		Ω(ctx.ResponseStatus()).Should(Equal(http.StatusOK))
		Ω(ctx.Value(jwt.JWTKey)).Should(Equal("TOKEN"))
		Ω(ctx.Value(jwt.JWTKey)).ShouldNot(Equal("bearer TOKEN"))
	})
})

type testHandler struct {
	Records []*log15.Record
}

func (t *testHandler) Log(r *log15.Record) error {
	t.Records = append(t.Records, r)
	return nil
}

type TestResponseWriter struct {
	ParentHeader http.Header
	Body         []byte
	Status       int
}

func (t *TestResponseWriter) Header() http.Header {
	return t.ParentHeader
}

func (t *TestResponseWriter) Write(b []byte) (int, error) {
	t.Body = append(t.Body, b...)
	return len(b), nil
}

func (t *TestResponseWriter) WriteHeader(s int) {
	t.Status = s
}
