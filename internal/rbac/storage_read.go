package rbac

import "context"

// PrivateStorageSlot is a storage slot outside WellKnownStorageSlots (slot 0).
// An eth_getStorageAt access check for it answers whether a viewer may read a
// contract's private storage, as decided by the storage-slot tier.
const PrivateStorageSlot = "0x0"

// CanReadPrivateStorage reports whether the viewer may read the private
// storage of addr in orgID. It is exactly the decision CheckAccess makes for
// eth_getStorageAt(addr, PrivateStorageSlot, "latest"): the method allowlist,
// contract access resolved as for any targeted read (grants, org-admin
// materialization, cross-org isolation), then the storage-slot tier, which
// admits private slots only with the admin claim on that contract.
//
// Responses that carry values derived from a contract's storage (client
// traces) use it, so they never show more than a direct storage read would.
// An error is returned for the caller to fail closed on.
func (c *AccessController) CanReadPrivateStorage(ctx context.Context, userExternalID, orgID, addr string, bypassCache bool) (bool, error) {
	res, err := c.CheckAccess(ctx, &AccessCheckRequest{
		UserExternalID: userExternalID,
		OrgID:          orgID,
		Method:         MethodGetStorageAt,
		Params:         []any{addr, PrivateStorageSlot, "latest"},
		TargetAddress:  addr,
		BypassCache:    bypassCache,
	})
	if err != nil {
		return false, err
	}
	return res != nil && res.Allowed && res.OrgID == orgID, nil
}
