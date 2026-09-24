package approvalpb

import "testing"

// The method names are the wire contract shared with the Java and Rust
// receivers; renaming one silently breaks delivery.
func TestMethodNamesAreTheContract(t *testing.T) {
	for got, want := range map[string]string{
		ApprovalDelivery_Deliver_FullMethodName: "/ops.approvals.v1.ApprovalDelivery/Deliver",
		ApprovalDelivery_Status_FullMethodName:  "/ops.approvals.v1.ApprovalDelivery/Status",
	} {
		if got != want {
			t.Fatalf("method %q, want %q", got, want)
		}
	}
}
