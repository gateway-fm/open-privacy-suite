// Development-only key generation and Ethereum signing for the isolated stack.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	var request struct {
		Action, Secret, Message, To, Data string
		Nonce                             uint64
		GasPrice                          uint64
	}
	if err := json.NewDecoder(os.Stdin).Decode(&request); err != nil {
		return err
	}
	result := map[string]any{}
	// Public development key. Never funded outside this disposable genesis.
	key, err := crypto.HexToECDSA(strings.Repeat("0", 63) + "1")
	if err != nil {
		return err
	}
	result["sender"] = strings.ToLower(crypto.PubkeyToAddress(key.PublicKey).Hex())
	switch request.Action {
	case "keys":
		pub, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(request.Secret), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		result["publicKey"] = base64.StdEncoding.EncodeToString(pub)
		result["seed"] = base64.StdEncoding.EncodeToString(private.Seed())
		result["bcrypt"] = string(hash)
	case "message":
		signature, err := crypto.Sign(accounts.TextHash([]byte(request.Message)), key)
		if err != nil {
			return err
		}
		signature[64] += 27
		result["signature"] = "0x" + hex.EncodeToString(signature)
	case "transaction":
		data, err := hex.DecodeString(strings.TrimPrefix(request.Data, "0x"))
		if err != nil {
			return err
		}
		var target *common.Address
		if request.To != "" {
			if !common.IsHexAddress(request.To) {
				return fmt.Errorf("invalid target")
			}
			addr := common.HexToAddress(request.To)
			target = &addr
		}
		if request.GasPrice == 0 {
			request.GasPrice = 2000000000
		}
		tx := types.NewTx(&types.LegacyTx{Nonce: request.Nonce, To: target, Gas: 1000000, GasPrice: new(big.Int).SetUint64(request.GasPrice), Data: data})
		signed, err := types.SignTx(tx, types.NewEIP155Signer(big.NewInt(31337)), key)
		if err != nil {
			return err
		}
		raw, err := signed.MarshalBinary()
		if err != nil {
			return err
		}
		result["raw"] = "0x" + hex.EncodeToString(raw)
		result["hash"] = strings.ToLower(signed.Hash().Hex())
		result["created"] = strings.ToLower(crypto.CreateAddress(crypto.PubkeyToAddress(key.PublicKey), request.Nonce).Hex())
	default:
		return fmt.Errorf("unknown action")
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}
