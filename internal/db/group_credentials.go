package db

import "context"

// RotateGroupRPCCredential changes only operational secret material. It cannot
// create access rows or alter declaratively owned methods, claims or flags.
func (d *DB) RotateGroupRPCCredential(ctx context.Context, orgID, groupID string, key *string) error {
	return d.WithTx(ctx, func(tx *Tx) error {
		result, err := tx.tx.ExecContext(ctx, `UPDATE group_access ga SET rpc_api_key=$3,updated_at=NOW() FROM groups g WHERE ga.group_id=g.id AND g.id=$1 AND g.org_id=$2`, groupID, orgID, key)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return ErrConfigurationForbidden
		}
		return tx.InvalidateCacheForOrg(ctx, orgID)
	})
}
