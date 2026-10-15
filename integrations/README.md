# Node integration inputs

The shared V1 signed-approval contract is maintained in
[`ops-node-integrations`](https://github.com/gateway-fm/ops-node-integrations).
`approvals-contract.lock.json` pins its commit, contract version and manifest hash.
The accompanying manifest records every protocol input's SHA-256 hash.

OPS vendors the protobuf and four test vectors for offline Go builds. They are imported inputs;
change the canonical contract through an integration-repository PR, then update this pin and run:

```sh
python3 scripts/approval_contract.py --sync
python3 scripts/approval_contract.py --upstream
go generate ./internal/nodeapproval/approvalpb
go test -race ./internal/nodeapproval/...
```

Go binding generation uses protoc 28.2, protoc-gen-go v1.36.11 and protoc-gen-go-grpc v1.6.1,
matching the committed generated headers. CI installs those exact versions and rejects generated
binding drift; update generator pins deliberately alongside the generated files.

`python3 scripts/approval_contract.py` checks the local inputs without network access. CI verifies
the exact upstream commit too, then checks the inputs again after the sender tests. A changed
protobuf or regenerated golden file cannot pass by being committed only in OPS. Existing golden
export flags are for proposing changes in a disposable checkout; submit those outputs to the
contract owner and update the reviewed pin before using them here.

This pin covers the contract only. The native source, dependency checks and local demo builds
remain in OPS during the migration. They will move to verified release bundles or digest-pinned
images after the standalone repository publishes qualified artifacts. No placeholder artifact
checksums or release tags are used. The separate OPS V2 policy runtime is not changed by this pin.
