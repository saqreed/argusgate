package rules

import "testing"

func TestCatalogIsStableCompleteAndSorted(t *testing.T) {
	entries := List()
	if len(entries) == 0 {
		t.Fatal("rule catalog is empty")
	}
	seen := make(map[string]struct{}, len(entries))
	for i, entry := range entries {
		if entry.ID == "" || entry.Title == "" || entry.Category == "" || entry.Confidence == "" {
			t.Fatalf("incomplete rule entry: %#v", entry)
		}
		if _, exists := seen[entry.ID]; exists {
			t.Fatalf("duplicate rule ID %s", entry.ID)
		}
		seen[entry.ID] = struct{}{}
		if i > 0 && entries[i-1].ID >= entry.ID {
			t.Fatalf("catalog is not sorted: %s before %s", entries[i-1].ID, entry.ID)
		}
		if found, ok := Find(entry.ID); !ok || found != entry {
			t.Fatalf("Find(%s) did not return the catalog entry", entry.ID)
		}
	}
	for _, required := range []string{"AG-TP001", "AG-MCP007", "AG-POL010", "AG-BASE004", "AG-SCAN001"} {
		if _, ok := seen[required]; !ok {
			t.Fatalf("missing required rule %s", required)
		}
	}
}
