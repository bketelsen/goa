package jwt_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/raphael/goa/jwt"
)

var _ = Describe("valid JWT DSL", func() {
	var dsl func()
	var spec jwt.Specification
	var dslErrors error

	JustBeforeEach(func() {
		spec, dslErrors = jwt.New(dsl)
		Ω(dslErrors).ShouldNot(HaveOccurred())
	})

	Context("with an empty DSL", func() {
		BeforeEach(func() {
			dsl = nil
		})

		It("returns an empty spec", func() {
			Ω(spec).ShouldNot(BeNil())
			Ω(spec).Should(HaveLen(0))
		})
	})

	Context("TTL", func() {
		const TTL = 60

		BeforeEach(func() {
			dsl = func() {
				jwt.TTL(60, func() {})
			}
		})

		It("sets the JWT TTL", func() {
			Ω(spec).ShouldNot(BeNil())
			Ω(spec[0].TTL).Should(Equal(TTL))
		})

	})
})

var _ = Describe("invalid JWT DSL", func() {
	var dsl func()
	var spec jwt.Specification
	var dslErrors error

	JustBeforeEach(func() {
		spec, dslErrors = jwt.New(dsl)
	})

	Context("invalid top level", func() {
		BeforeEach(func() {
			dsl = func() {
				jwt.TTL(-60, func() {})
			}
		})

		It("returns a nil spec and an error", func() {
			Ω(spec).Should(BeNil())
			Ω(dslErrors).ShouldNot(BeNil())
			Ω(dslErrors.Error()).Should(ContainSubstring("invalid JWT specification"))
		})

	})

})
