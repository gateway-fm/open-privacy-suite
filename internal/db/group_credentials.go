package db

import "context"

// RotateGroupRPCCredential changes only operational secret material. It cannot
// create access rows or alter declaratively owned methods, claims or flags,
// and it yields to a credential the group's configuration document declares:
// one owner per field, so the document is changed instead.
func (d *DB) RotateGroupRPCCredential(ctx context.Context, orgID, groupID string, key *string) error {
	return d.WithTx(ctx, func(tx *Tx) error {
		result, err := tx.tx.ExecContext(ctx, `UPDATE group_access ga SET rpc_api_key=$3,updated_at=NOW() FROM groups g WHERE ga.group_id=g.id AND g.id=$1 AND g.org_id=$2 AND ga.rpc_api_key_source IS NULL`, groupID, orgID, key)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			var declared bool
			if err := tx.tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM group_access ga JOIN groups g ON g.id=ga.group_id WHERE g.id=$1 AND g.org_id=$2 AND ga.rpc_api_key_source IS NOT NULL)`, groupID, orgID).Scan(&declared); err != nil {
				return err
			}
			if declared {
				return ConfigurationConflict("the group's credential is declared by its configuration document; change the document instead")
			}
			return ErrConfigurationForbidden
		}
		return tx.InvalidateCacheForOrg(ctx, orgID)
	})
}
