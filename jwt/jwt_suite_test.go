package jwt_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestJWT(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "JWT Suite")
}
