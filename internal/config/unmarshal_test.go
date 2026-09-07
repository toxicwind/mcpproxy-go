package config

import (
	"encoding/json"
	"testing"
)

func TestConfigUnmarshalBothFormats(t *testing.T) {
	arrayJSON := []byte(`{
		"listen": "127.0.0.1:8080",
		"mcpServers": [
			{"name": "server1", "command": "npx", "args": ["foo"]},
			{"name": "server2", "url": "http://example.com"}
		]
	}`)

	mapJSON := []byte(`{
		"listen": "127.0.0.1:8080",
		"mcpServers": {
			"server1": {"command": "npx", "args": ["foo"]},
			"server2": {"url": "http://example.com"}
		}
	}`)

	var cfgArray Config
	if err := json.Unmarshal(arrayJSON, &cfgArray); err != nil {
		t.Fatalf("Failed to unmarshal array format: %v", err)
	}

	if len(cfgArray.Servers) != 2 {
		t.Fatalf("Expected 2 servers from array, got %d", len(cfgArray.Servers))
	}

	var cfgMap Config
	if err := json.Unmarshal(mapJSON, &cfgMap); err != nil {
		t.Fatalf("Failed to unmarshal map format: %v", err)
	}

	if len(cfgMap.Servers) != 2 {
		t.Fatalf("Expected 2 servers from map, got %d", len(cfgMap.Servers))
	}

	// Verify server names populated
	if cfgMap.Servers[0].Name != "server1" || cfgMap.Servers[1].Name != "server2" {
		t.Errorf("Unexpected server names from map: %v, %v", cfgMap.Servers[0].Name, cfgMap.Servers[1].Name)
	}
}
