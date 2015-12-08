package jwt

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

type (

	// ResourceDefinition represents a JWT resource as defined by its path (or path prefix).
	ResourceDefinition struct {
		// TTL represents the TTL for the token in seconds
		TTL int
	}

	// Specification contains the information needed to handle JWT requests
	Specification []*ResourceDefinition
)

var (
	// spec is the CORS specification being built by the DSL.
	spec Specification

	// dslErrors contain errors encountered when running the DSL.
	dslErrors []error
)

// New runs the given CORS specification DSL and returns the built-up data structure.
func New(dsl func()) (Specification, error) {
	spec = Specification{}
	dslErrors = nil
	if dsl == nil {
		return spec, nil
	}
	dsl()
	if len(dslErrors) > 0 {
		msg := make([]string, len(dslErrors))
		for i, e := range dslErrors {
			msg[i] = e.Error()
		}
		return nil, fmt.Errorf("invalid JWT specification: %s", strings.Join(msg, ", "))
	}
	res := make([]*ResourceDefinition, len(spec))
	for i, r := range spec {
		res[i] = r
	}
	return Specification(res), nil
}

//
func TTL(ttl int, dsl func()) {
	if ttl > 0 {
		res := &ResourceDefinition{TTL: ttl}
		spec = append(spec, res)
	} else {
		dslErrors = append(dslErrors, fmt.Errorf("invalid TTL, must be greater than 0"))
	}
}

// String returns a human friendly representation of the CORS specification.
func (v Specification) String() string {
	if spec[0].TTL == 0 {
		return "<empty JWT specification>"
	}
	b := &bytes.Buffer{}

	if spec[0].TTL > 0 {
		b.WriteString("TTL: ")
		b.WriteString(strconv.Itoa(spec[0].TTL))
		b.WriteString("\n")
	}

	return b.String()
}
