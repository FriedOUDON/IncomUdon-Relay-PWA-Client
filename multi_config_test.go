package main

import "testing"

func TestParseMultiMaxSlots(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    int
		wantErr bool
	}{
		{name: "default", input: "", want: defaultMultiMaxSlots},
		{name: "minimum", input: "1", want: 1},
		{name: "maximum", input: "10", want: 10},
		{name: "too low", input: "0", wantErr: true},
		{name: "too high", input: "11", wantErr: true},
		{name: "not numeric", input: "four", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseMultiMaxSlots(test.input)
			if test.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != test.want {
				t.Fatalf("got %d, want %d", got, test.want)
			}
		})
	}
}

func TestResolveMultiPath(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		base    string
		want    string
		wantErr bool
	}{
		{name: "root default", base: "", want: "/multi"},
		{name: "base default", base: "/incomudon", want: "/incomudon/multi"},
		{name: "relative custom", input: "console", base: "/incomudon", want: "/incomudon/console"},
		{name: "absolute custom", input: "/console", base: "/incomudon", want: "/console"},
		{name: "root rejected", input: "/", wantErr: true},
		{name: "base rejected", input: "/incomudon", base: "/incomudon", wantErr: true},
		{name: "websocket rejected", input: "/incomudon/ws", base: "/incomudon", wantErr: true},
		{name: "auth rejected", input: "/incomudon/auth/login", base: "/incomudon", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := resolveMultiPath(test.input, test.base)
			if test.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != test.want {
				t.Fatalf("got %q, want %q", got, test.want)
			}
		})
	}
}

func TestParseMultiDefaultSlots(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		maximum int
		want    int
		wantErr bool
	}{
		{name: "default", input: "", maximum: 10, want: defaultMultiDefaultSlots},
		{name: "default capped", input: "", maximum: 2, want: 2},
		{name: "minimum", input: "1", maximum: 10, want: 1},
		{name: "maximum", input: "6", maximum: 6, want: 6},
		{name: "too low", input: "0", maximum: 10, wantErr: true},
		{name: "above configured maximum", input: "7", maximum: 6, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseMultiDefaultSlots(test.input, test.maximum)
			if test.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != test.want {
				t.Fatalf("got %d, want %d", got, test.want)
			}
		})
	}
}
