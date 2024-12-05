//go:build !disable_pgv

// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: envoy/data/core/v3/tlv_metadata.proto

package corev3

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/types/known/anypb"
)

// ensure the imports are used
var (
	_ = bytes.MinRead
	_ = errors.New("")
	_ = fmt.Print
	_ = utf8.UTFMax
	_ = (*regexp.Regexp)(nil)
	_ = (*strings.Reader)(nil)
	_ = net.IPv4len
	_ = time.Duration(0)
	_ = (*url.URL)(nil)
	_ = (*mail.Address)(nil)
	_ = anypb.Any{}
	_ = sort.Sort
)

// Validate checks the field values on TlvsMetadata with the rules defined in
// the proto definition for this message. If any rules are violated, the first
// error encountered is returned, or nil if there are no violations.
func (m *TlvsMetadata) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on TlvsMetadata with the rules defined
// in the proto definition for this message. If any rules are violated, the
// result is a list of violation errors wrapped in TlvsMetadataMultiError, or
// nil if none found.
func (m *TlvsMetadata) ValidateAll() error {
	return m.validate(true)
}

func (m *TlvsMetadata) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	// no validation rules for TypedMetadata

	if len(errors) > 0 {
		return TlvsMetadataMultiError(errors)
	}

	return nil
}

// TlvsMetadataMultiError is an error wrapping multiple validation errors
// returned by TlvsMetadata.ValidateAll() if the designated constraints aren't met.
type TlvsMetadataMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m TlvsMetadataMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m TlvsMetadataMultiError) AllErrors() []error { return m }

// TlvsMetadataValidationError is the validation error returned by
// TlvsMetadata.Validate if the designated constraints aren't met.
type TlvsMetadataValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e TlvsMetadataValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e TlvsMetadataValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e TlvsMetadataValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e TlvsMetadataValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e TlvsMetadataValidationError) ErrorName() string { return "TlvsMetadataValidationError" }

// Error satisfies the builtin error interface
func (e TlvsMetadataValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sTlvsMetadata.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = TlvsMetadataValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = TlvsMetadataValidationError{}
