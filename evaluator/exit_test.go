package main

import "testing"

func TestExitCode_GateUnmanagedFails(t *testing.T) {
	s := Summary{Unmanaged: 1}
	if got := ExitCode(ModeGate, s); got != 1 {
		t.Errorf("ExitCode(gate, unmanaged=1) = %d; want 1", got)
	}
}

func TestExitCode_GateExpiredFails(t *testing.T) {
	s := Summary{Expired: 1}
	if got := ExitCode(ModeGate, s); got != 1 {
		t.Errorf("ExitCode(gate, expired=1) = %d; want 1", got)
	}
}

func TestExitCode_GateCleanPasses(t *testing.T) {
	s := Summary{Total: 5, Suppressed: 5}
	if got := ExitCode(ModeGate, s); got != 0 {
		t.Errorf("ExitCode(gate, all suppressed) = %d; want 0", got)
	}
}

func TestExitCode_GateNoFindingsPasses(t *testing.T) {
	if got := ExitCode(ModeGate, Summary{}); got != 0 {
		t.Errorf("ExitCode(gate, empty) = %d; want 0", got)
	}
}

func TestExitCode_InformAlwaysZero(t *testing.T) {
	cases := []Summary{
		{},
		{Unmanaged: 5},
		{Expired: 3},
		{Unmanaged: 5, Expired: 3},
	}
	for _, s := range cases {
		if got := ExitCode(ModeInform, s); got != 0 {
			t.Errorf("ExitCode(inform, %+v) = %d; want 0", s, got)
		}
	}
}
