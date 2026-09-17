package configuration

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Every exported validator reports faults in the caller's authored document as
// a *SourceError so handlers can return the text and nothing else (RD-934).
func TestAuthoredDocumentFaultsAreSourceErrors(t *testing.T) {
	_, parseErr := Parse(nil)
	_, ciRequestErr := ParseCIActivationRequest(nil)
	_, ciApprovalErr := ParseCIApproval(nil)
	verifyErr := VerifyCIApproval(nil, ApproversSpec{}, Scope{Kind: "organization"}, "svc", nil, time.Now())
	approversErr := ValidateApprovers(ApproversSpec{GroupIDs: []string{"missing"}}, nil)
	_, diffApproversErr := DiffApprovers(&Document{Kind: Groups}, nil)
	_, diffGroupsErr := DiffGroups(&Document{Kind: Platform}, GroupSnapshot{})
	_, diffRegistryErr := DiffRegistry(&Document{Kind: Platform}, RegistrySnapshot{})
	_, diffComplianceErr := DiffCompliance(&Document{Kind: Platform}, ComplianceSnapshot{})
	_, diffPlatformErr := DiffPlatform(&Document{Kind: Groups}, PlatformSnapshot{})
	for name, err := range map[string]error{
		"parse": parseErr, "ci request": ciRequestErr, "ci approval": ciApprovalErr, "verify": verifyErr,
		"approvers": approversErr, "diff approvers": diffApproversErr, "diff groups": diffGroupsErr,
		"diff registry": diffRegistryErr, "diff compliance": diffComplianceErr, "diff platform": diffPlatformErr,
	} {
		t.Run(name, func(t *testing.T) {
			require.Error(t, err)
			var typed *SourceError
			require.ErrorAs(t, err, &typed)
			require.Equal(t, err.Error(), typed.ClientMessage())
			require.NotNil(t, errors.Unwrap(err))
		})
	}
	_, _, err := ExportRegistry(nil)
	require.NoError(t, err, "success returns a nil error, not a typed nil")
}
