package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"slices"
	"testing"
)

func TestConventionAttributeNames(t *testing.T) {
	for _, convention := range []AttributeConvention{"", AttributeConventionDefault} {
		names, err := conventionAttributeNames(convention)
		if err != nil {
			t.Fatalf("convention %q: %v", convention, err)
		}
		if names != defaultAttributeNames {
			t.Errorf("convention %q did not resolve to the semantic conventions", convention)
		}
	}
	names, err := conventionAttributeNames(AttributeConventionECS)
	if err != nil {
		t.Fatal(err)
	}
	if names != ecsAttributeNames {
		t.Error(`convention "ecs" did not resolve to the Elastic Common Schema`)
	}

	// The conventions adopted most of these fields from ECS, so they name all
	// but the class of event, the application protocol and its version
	// identically. A further difference needs a row in the README table, and
	// this is what says so.
	var differing []string
	defaults, ecs := reflect.ValueOf(defaultAttributeNames), reflect.ValueOf(ecsAttributeNames)
	for i := range defaults.NumField() {
		// String, not Interface: the fields are unexported, and every one of
		// them is an attribute.Key.
		if defaults.Field(i).String() != ecs.Field(i).String() {
			differing = append(differing, defaults.Type().Field(i).Name)
		}
	}
	want := []string{"networkProtocolName", "networkProtocolVersion", "eventName"}
	if !slices.Equal(differing, want) {
		t.Errorf("the conventions differ in %v, want %v", differing, want)
	}
	if ecsAttributeNames.networkProtocolVersion != "" {
		t.Error("ECS has no name for the protocol version, want the attribute dropped")
	}

	if _, err := conventionAttributeNames("nonsense"); err == nil {
		t.Error("an unknown convention should be refused")
	}
}

func TestErrorType(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{io.EOF, "eof"},
		{io.ErrUnexpectedEOF, "eof"},
		{context.Canceled, "canceled"},
		{context.DeadlineExceeded, "timeout"},
		{os.ErrDeadlineExceeded, "timeout"},
		{net.ErrClosed, "closed"},
		{fmt.Errorf("wrapped: %w", os.ErrDeadlineExceeded), "timeout"},
		{errors.New("boom"), "other"},
	}
	for _, tc := range cases {
		if got := errorType(tc.err); got != tc.want {
			t.Errorf("errorType(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}
