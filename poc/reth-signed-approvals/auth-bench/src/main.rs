//! Isolated cryptographic microbenchmark. Does not change OPS or Reth authentication.
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::AeadInPlace};
use ed25519_dalek::{Signature, Signer, SigningKey};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::{hint::black_box, time::Instant};

type Hmac256 = Hmac<Sha256>;
const DOMAIN: &[u8] = b"OPS_APPROVAL_V1\0";
const COUNT: usize = 256;

struct Fixture {
    message: Vec<u8>,
    signature: Signature,
    signature_hex: String,
    mac: [u8; 32],
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
    tag: aes_gcm::Tag,
}

fn timed(count: usize, mut op: impl FnMut(usize)) -> f64 {
    let start = Instant::now();
    for i in 0..count {
        op(i % COUNT);
    }
    start.elapsed().as_nanos() as f64 / count as f64 / 1000.0
}

fn main() {
    // Public fixture keys only. Unique encryption nonce per fixture, no encryptions
    // inside the timed loop. Repeated decryption is a benchmark, not a wire protocol.
    let signer = SigningKey::from_bytes(&[7; 32]);
    let verifier = signer.verifying_key();
    let hmac_key = [9; 32];
    let hmac_template = <Hmac256 as Mac>::new_from_slice(&hmac_key).unwrap();
    let cipher = Aes256Gcm::new_from_slice(&[11; 32]).unwrap();
    let fixtures: Vec<_> = (0..COUNT)
        .map(|i| {
            let mut message = DOMAIN.to_vec();
            message.extend_from_slice(&31337u64.to_be_bytes());
            for field in 0..3 {
                let mut word = [field + 1; 32];
                word[..8].copy_from_slice(&(i as u64).to_be_bytes());
                message.extend_from_slice(&word);
            }
            let signature = signer.sign(&message);
            let mut mac = hmac_template.clone();
            mac.update(&message);
            let mac = mac.finalize().into_bytes().into();
            let mut nonce = [0u8; 12];
            nonce[4..].copy_from_slice(&(i as u64).to_be_bytes());
            let mut ciphertext = message.clone();
            let tag = cipher
                .encrypt_in_place_detached(
                    Nonce::from_slice(&nonce),
                    b"auth-bench-v1",
                    &mut ciphertext,
                )
                .unwrap();
            Fixture {
                message,
                signature,
                signature_hex: hex::encode(signature.to_bytes()),
                mac,
                nonce,
                ciphertext,
                tag,
            }
        })
        .collect();

    // Reject tampering in every approval field; validate roundtrip before timing.
    for f in &fixtures {
        assert!(verifier.verify_strict(&f.message, &f.signature).is_ok());
        let mut m = hmac_template.clone();
        m.update(&f.message);
        assert!(m.verify_slice(&f.mac).is_ok());
        let mut plaintext = f.ciphertext.clone();
        cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&f.nonce),
                b"auth-bench-v1",
                &mut plaintext,
                &f.tag,
            )
            .unwrap();
        assert_eq!(plaintext, f.message);
        for offset in [
            0,
            DOMAIN.len(),
            DOMAIN.len() + 8,
            DOMAIN.len() + 40,
            DOMAIN.len() + 72,
        ] {
            let mut altered = f.message.clone();
            altered[offset] ^= 1;
            assert!(verifier.verify_strict(&altered, &f.signature).is_err());
            let mut mac = hmac_template.clone();
            mac.update(&altered);
            assert!(mac.verify_slice(&f.mac).is_err());
        }
        let mut wrong_tag = f.mac;
        wrong_tag[0] ^= 1;
        let mut mac = hmac_template.clone();
        mac.update(&f.message);
        assert!(mac.verify_slice(&wrong_tag).is_err());
        let mut wrong_ciphertext = f.ciphertext.clone();
        wrong_ciphertext[0] ^= 1;
        assert!(
            cipher
                .decrypt_in_place_detached(
                    Nonce::from_slice(&f.nonce),
                    b"auth-bench-v1",
                    &mut wrong_ciphertext,
                    &f.tag
                )
                .is_err()
        );
    }
    // RFC 4231 test case 1, HMAC-SHA-256.
    let mut known = <Hmac256 as Mac>::new_from_slice(&[0x0b; 20]).unwrap();
    known.update(b"Hi There");
    assert_eq!(
        hex::encode(known.finalize().into_bytes()),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );

    // One ordinary strict Ed25519 signature over 32 complete approvals. This is
    // signed-message aggregation, not Dalek verify_batch() or a new primitive.
    // Collection delay and per-approval dispatch are explicitly outside this test.
    let batch_domain = b"OPS_APPROVAL_BATCH_BENCH_V1\0";
    let batches: Vec<_> = fixtures
        .as_chunks::<32>()
        .0
        .iter()
        .map(|chunk| {
            let mut message = batch_domain.to_vec();
            message.extend_from_slice(&32u32.to_be_bytes());
            for f in chunk {
                message.extend_from_slice(&f.message);
            }
            let signature = signer.sign(&message);
            assert!(verifier.verify_strict(&message, &signature).is_ok());
            for member in 0..32 {
                let mut altered = message.clone();
                altered[batch_domain.len() + 4 + member * chunk[0].message.len()] ^= 1;
                assert!(verifier.verify_strict(&altered, &signature).is_err());
            }
            (message, signature)
        })
        .collect();

    let methods = [
        "ed25519_strict",
        "ed25519_with_hex_and_message_allocation",
        "ed25519_signed_batch_32_per_approval",
        "hmac_sha256_prepared_key",
        "hmac_sha256_new_context",
        "aes256_gcm_decrypt_only",
    ];
    let mut raw = Vec::new();
    for sample in 0..10 {
        for shift in 0..methods.len() {
            let method = methods[(shift + sample) % methods.len()];
            let count = if method.starts_with("ed25519") {
                20_000
            } else {
                500_000
            };
            let us = match method {
                "ed25519_strict" => timed(count, |i| {
                    let f = black_box(&fixtures[i]);
                    assert!(
                        black_box(&verifier)
                            .verify_strict(black_box(&f.message), black_box(&f.signature))
                            .is_ok()
                    );
                }),
                "ed25519_with_hex_and_message_allocation" => timed(count, |i| {
                    let f = black_box(&fixtures[i]);
                    let bytes = hex::decode(black_box(&f.signature_hex)).unwrap();
                    let signature = Signature::from_slice(&bytes).unwrap();
                    let mut message = DOMAIN.to_vec();
                    message.extend_from_slice(&f.message[DOMAIN.len()..DOMAIN.len() + 8]);
                    for word in f.message[DOMAIN.len() + 8..].as_chunks::<32>().0.iter() {
                        message.extend_from_slice(word);
                    }
                    assert!(
                        black_box(&verifier)
                            .verify_strict(black_box(&message), black_box(&signature))
                            .is_ok()
                    );
                }),
                "ed25519_signed_batch_32_per_approval" => {
                    timed(count, |i| {
                        let (message, signature) = black_box(&batches[i % batches.len()]);
                        assert!(
                            black_box(&verifier)
                                .verify_strict(black_box(message), black_box(signature))
                                .is_ok()
                        );
                    }) / 32.0
                }
                "hmac_sha256_prepared_key" => timed(count, |i| {
                    let f = black_box(&fixtures[i]);
                    let mut mac = black_box(&hmac_template).clone();
                    mac.update(black_box(&f.message));
                    assert!(mac.verify_slice(black_box(&f.mac)).is_ok());
                }),
                "hmac_sha256_new_context" => timed(count, |i| {
                    let f = black_box(&fixtures[i]);
                    let mut mac = <Hmac256 as Mac>::new_from_slice(black_box(&hmac_key)).unwrap();
                    mac.update(black_box(&f.message));
                    assert!(mac.verify_slice(black_box(&f.mac)).is_ok());
                }),
                "aes256_gcm_decrypt_only" => timed(count, |i| {
                    let f = black_box(&fixtures[i]);
                    let mut plaintext = f.ciphertext.clone();
                    black_box(&cipher)
                        .decrypt_in_place_detached(
                            Nonce::from_slice(black_box(&f.nonce)),
                            b"auth-bench-v1",
                            black_box(&mut plaintext),
                            black_box(&f.tag),
                        )
                        .unwrap();
                    black_box(plaintext);
                }),
                _ => unreachable!(),
            };
            if sample != 0 {
                raw.push(serde_json::json!({"method":method,"sample":sample,"iterations":count,"approvals_per_operation":if method == "ed25519_signed_batch_32_per_approval" {32} else {1},"us_per_verification":us}));
            }
        }
    }
    let summary: Vec<_> = methods.iter().map(|method| {
        let mut times: Vec<_> = raw.iter().filter(|r| r["method"]==*method).map(|r| r["us_per_verification"].as_f64().unwrap()).collect();
        times.sort_by(f64::total_cmp);
        serde_json::json!({"method":method,"median_us":times[times.len()/2],"range_us":[times[0],times[times.len()-1]],"samples":times.len()})
    }).collect();
    println!("{}",serde_json::to_string_pretty(&serde_json::json!({
        "method":"Single-thread in-memory cryptographic primitives, release build, 256 varying fixtures, black_box, rotated method order, one warmup sample discarded, nine measured samples. Signature/MAC generation and key setup excluded except the explicitly named new-context HMAC variant. AES-GCM includes a ciphertext-buffer allocation but is NOT a TLS benchmark. No network, JSON parsing, OPS preflight, or Reth execution.",
        "message_bytes":fixtures[0].message.len(),"correctness":"256 valid fixtures; tampering in domain/chain/tx/fingerprint/principal rejected for both Ed25519 and HMAC; modified HMAC tags and AES-GCM ciphertext rejected; AES roundtrip and RFC4231 HMAC vector pass.",
        "summary":summary,"raw":raw
    })).unwrap());
}
