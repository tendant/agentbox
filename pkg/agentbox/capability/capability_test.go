package capability

import (
	"encoding/json"
	"reflect"
	"sort"
	"testing"
)

func TestRegistry(t *testing.T) {
	ids := IDs()
	if len(ids) != len(Registry) || !sort.SliceIsSorted(ids, func(i, j int) bool { return ids[i] < ids[j] }) {
		t.Fatalf("IDs: %v", ids)
	}
	for id, d := range Registry {
		if d.ID != id || d.Description == "" || len(d.Tests) == 0 {
			t.Errorf("%s: incomplete definition %+v", id, d)
		}
	}
}

func TestEvaluate(t *testing.T) {
	res := Evaluate("seatbelt",
		[]ID{FSDeny, NetworkRestrictedEgress, KernelIsolation},
		[]ID{NetworkRestrictedEgress, FSDeny, FSDeny},
		[]string{"host kernel"})
	if !reflect.DeepEqual(res.Enforced, []ID{FSDeny, NetworkRestrictedEgress}) {
		t.Errorf("enforced %v", res.Enforced)
	}
	if len(res.Gaps) != 1 || res.Gaps[0].Capability != KernelIsolation {
		t.Errorf("gaps %v", res.Gaps)
	}
	// The JSON shape is part of the audit record's policy snapshot.
	b, _ := json.Marshal(res)
	want := `{"backend":"seatbelt","enforced":["fs.deny","network.restricted_egress"],"gaps":[{"capability":"kernel.isolation","reason":"not enforced by backend"}],"caveats":["host kernel"]}`
	if string(b) != want {
		t.Errorf("json %s", b)
	}
}
