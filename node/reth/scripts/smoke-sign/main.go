// Generates public, deterministic development transactions for smoke.py.
package main

import (
	"encoding/hex"
	"encoding/json"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"math/big"
	"os"
)

func main() {
	key, err := crypto.HexToECDSA("0000000000000000000000000000000000000000000000000000000000000001")
	if err != nil {
		panic(err)
	}
	sender := crypto.PubkeyToAddress(key.PublicKey)
	target := common.HexToAddress("0x1f98431c8ad98523631ae4a59f267346ea31f984")
	data := append(common.FromHex("0xa9059cbb"), common.LeftPadBytes(sender.Bytes(), 32)...)
	data = append(data, common.LeftPadBytes([]byte{1}, 32)...)
	out := map[string]any{"sender": sender.Hex(), "target": target.Hex(), "data": "0x" + hex.EncodeToString(data)}
	for _, spec := range []struct {
		name  string
		nonce uint64
		to    *common.Address
		data  []byte
	}{{"call", 0, &target, data}, {"create", 1, nil, common.FromHex("0x600060005360016000f3")}, {"denied", 2, &target, data}} {
		tx, err := types.SignTx(types.NewTx(&types.LegacyTx{Nonce: spec.nonce, To: spec.to, Data: spec.data, Gas: 300000, GasPrice: big.NewInt(2000000000), Value: big.NewInt(0)}), types.NewEIP155Signer(big.NewInt(31337)), key)
		if err != nil {
			panic(err)
		}
		raw, err := tx.MarshalBinary()
		if err != nil {
			panic(err)
		}
		out[spec.name] = map[string]string{"raw": "0x" + hex.EncodeToString(raw), "hash": tx.Hash().Hex()}
	}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		panic(err)
	}
}
