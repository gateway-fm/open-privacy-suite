// Deterministic public development keys only; transaction generation is outside
// the measured load interval. No OPS, wallet, or production key is accessed.
package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"math/big"
	"os"
)

func main() {
	count := flag.Int("count", 768, "transactions, plus one denial probe")
	senders := flag.Int("senders", 8, "public development signers")
	target := flag.String("target", "0x1f98431c8ad98523631ae4a59f267346ea31f984", "destination")
	data := flag.String("data", "0x", "calldata")
	flag.Parse()
	if *count < 1 || *senders < 1 || *senders > 1000 {
		panic("invalid workload size")
	}
	keys := make([]*ecdsa.PrivateKey, *senders)
	addresses := make([]string, *senders)
	for i := range keys {
		var err error
		keys[i], err = crypto.HexToECDSA(fmt.Sprintf("%064x", i+1))
		if err != nil {
			panic(err)
		}
		addresses[i] = crypto.PubkeyToAddress(keys[i].PublicKey).Hex()
	}
	to := common.HexToAddress(*target)
	transactions := make([]map[string]any, 0, *count+1)
	for i := 0; i <= *count; i++ {
		signer := i % *senders
		tx, err := types.SignTx(types.NewTx(&types.LegacyTx{Nonce: uint64(i / *senders), To: &to, Data: common.FromHex(*data), Gas: 300000, GasPrice: big.NewInt(2000000000)}), types.NewEIP155Signer(big.NewInt(31337)), keys[signer])
		if err != nil {
			panic(err)
		}
		raw, err := tx.MarshalBinary()
		if err != nil {
			panic(err)
		}
		transactions = append(transactions, map[string]any{"hash": tx.Hash().Hex(), "raw": "0x" + hex.EncodeToString(raw), "signer": addresses[signer], "nonce": i / *senders})
	}
	if err := json.NewEncoder(os.Stdout).Encode(map[string]any{"senders": addresses, "transactions": transactions}); err != nil {
		panic(err)
	}
}
