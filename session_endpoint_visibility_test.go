package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEmitConnectedHidesManagedRelayEndpoint(t *testing.T) {
	var event serverEvent
	session := &relaySession{
		cfg: sessionConfig{
			RelayHost:         "relay.internal.example",
			RelayPort:         50000,
			HideRelayEndpoint: true,
		},
		cb: sessionCallbacks{
			onEvent: func(next serverEvent) {
				event = next
			},
		},
	}

	session.emitConnected()
	if event.RelayHost != "" || event.RelayPort != 0 {
		t.Fatalf("managed relay endpoint leaked in connected event: %#v", event)
	}
	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal connected event: %v", err)
	}
	if strings.Contains(string(payload), "relayHost") || strings.Contains(string(payload), "relayPort") {
		t.Fatalf("managed relay endpoint fields leaked in connected event JSON: %s", payload)
	}
}

func TestEmitConnectedExposesUserConfiguredRelayEndpoint(t *testing.T) {
	var event serverEvent
	session := &relaySession{
		cfg: sessionConfig{
			RelayHost: "relay.example",
			RelayPort: 50000,
		},
		cb: sessionCallbacks{
			onEvent: func(next serverEvent) {
				event = next
			},
		},
	}

	session.emitConnected()
	if event.RelayHost != "relay.example" || event.RelayPort != 50000 {
		t.Fatalf("user-configured relay endpoint was not included in connected event: %#v", event)
	}
}
