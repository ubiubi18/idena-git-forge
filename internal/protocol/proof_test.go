package protocol

import "testing"

func TestEligibleIdentityStates(t *testing.T) {
	for _, test := range []struct {
		state    uint16
		name     string
		eligible bool
	}{
		{state: 1, name: "Invite", eligible: false},
		{state: 2, name: "Candidate", eligible: false},
		{state: 3, name: "Verified", eligible: true},
		{state: 4, name: "Suspended", eligible: false},
		{state: 5, name: "Killed", eligible: false},
		{state: 6, name: "Zombie", eligible: false},
		{state: 7, name: "Newbie", eligible: true},
		{state: 8, name: "Human", eligible: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := IsEligibleIdentityState(test.state); got != test.eligible {
				t.Fatalf("IsEligibleIdentityState(%d) = %t, want %t", test.state, got, test.eligible)
			}
			if got := IdentityStateName(test.state); got != test.name {
				t.Fatalf("IdentityStateName(%d) = %q, want %q", test.state, got, test.name)
			}
		})
	}
}
