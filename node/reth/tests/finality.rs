use alloy_primitives::B256;
use ops_reth_policy::runtime::TransactionStatus;

fn included() -> TransactionStatus {
    TransactionStatus {
        status: "included".into(),
        facts_version: 7,
        block_hash: Some(B256::repeat_byte(2)),
        block_number: Some(10),
        reason_code: String::new(),
        created: Vec::new(),
        finalized: false,
        finalized_block_hash: None,
        finalized_block_number: None,
    }
}

#[test]
fn receipt_alone_or_noncanonical_receipt_never_proves_finality() {
    let mut status = included();
    assert!(!status.finalized);
    status.observe_finality(B256::repeat_byte(2), 9, B256::repeat_byte(1));
    assert!(!status.finalized);
    status.observe_finality(B256::repeat_byte(3), 11, B256::repeat_byte(4));
    assert!(!status.finalized);
    status.observe_finality(B256::repeat_byte(2), 10, B256::repeat_byte(4));
    assert!(!status.finalized);
    status.observe_finality(B256::repeat_byte(2), 11, B256::repeat_byte(4));
    assert!(status.finalized);
    assert_eq!(status.finalized_block_number, Some(11));
    assert_eq!(status.finalized_block_hash, Some(B256::repeat_byte(4)));
}

#[test]
fn pending_and_reorganized_status_cannot_keep_old_finality() {
    let mut status = included();
    status.observe_finality(B256::repeat_byte(2), 10, B256::repeat_byte(2));
    assert!(status.finalized);
    status.status = "pending".into();
    status.observe_finality(B256::repeat_byte(2), 10, B256::repeat_byte(2));
    assert!(!status.finalized);
    assert_eq!(status.finalized_block_hash, None);
    assert_eq!(status.finalized_block_number, None);
}
