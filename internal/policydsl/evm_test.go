package policydsl

import "testing"

// TestNewEVMEvaluator_RejectsBytecodeThatDoesNotMatchItsDigest keeps the digest
// load-bearing.
//
// An approval refers to the digest, so it has to be checked against the bytes
// rather than merely stored beside them. Anything that could alter stored
// bytecode while leaving the recorded digest, status and audit entry saying
// "approved" must not then be executed as though it were the approved artifact.
func TestNewEVMEvaluator_RejectsBytecodeThatDoesNotMatchItsDigest(t *testing.T) {
	_, err := NewEVMEvaluator(&Artifact{
		RuntimeBytecode: []byte{0x60, 0x80, 0x60, 0x40},
		RuntimeDigest:   "00000000000000000000000000000000000000000000000000000000deadbeef",
	})
	if err == nil {
		t.Fatal("bytecode that does not hash to its recorded digest was accepted")
	}
}

func TestNewEVMEvaluator_RejectsAnEmptyArtifact(t *testing.T) {
	if _, err := NewEVMEvaluator(nil); err == nil {
		t.Error("a nil artifact was accepted")
	}
	if _, err := NewEVMEvaluator(&Artifact{}); err == nil {
		t.Error("an artifact with no bytecode was accepted")
	}
}
