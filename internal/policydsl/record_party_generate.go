package policydsl

import (
	"fmt"
	"slices"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
)

func writeRecordPartyCheck(b *strings.Builder, rule int, arg compiledArg, headLen int) {
	r := arg.record
	fmt.Fprintf(b, "\n    function _record%d_%d(address[] calldata linked, bytes calldata payload, address target) internal view returns (uint16) {\n", rule, arg.index)
	b.WriteString("        bytes memory input;\n        {\n")
	fmt.Fprintf(b, "            uint256 word = uint256(bytes32(payload[%d:%d]));\n", arg.offset, arg.offset+32)
	if r.input.T == abi.StringTy || r.input.T == abi.BytesTy {
		fmt.Fprintf(b, "            if (word %% 32 != 0 || word < %d || word > payload.length - 36) return MALFORMED_CALLDATA;\n", headLen-4)
		b.WriteString("            uint256 start = 4 + word;\n")
		b.WriteString("            uint256 length = uint256(bytes32(payload[start:start + 32]));\n")
		fmt.Fprintf(b, "            if (length > %d) return MALFORMED_CALLDATA;\n", MaxRecordIDBytes)
		b.WriteString("            uint256 padded = (length + 31) / 32 * 32;\n")
		b.WriteString("            if (padded > payload.length - start - 32) return MALFORMED_CALLDATA;\n")
		b.WriteString("            for (uint256 p = start + 32 + length; p < start + 32 + padded; p++) { if (payload[p] != 0) return MALFORMED_CALLDATA; }\n")
		fmt.Fprintf(b, "            input = abi.encodeWithSelector(%s, payload[start + 32:start + 32 + length]);\n", solidityBytes4(r.selector))
	} else {
		if r.input.T == abi.UintTy && r.input.Size < 256 {
			fmt.Fprintf(b, "            if (word >> %d != 0) return MALFORMED_CALLDATA;\n", r.input.Size)
		}
		fmt.Fprintf(b, "            input = abi.encodePacked(%s, bytes32(word));\n", solidityBytes4(r.selector))
	}
	b.WriteString("        }\n")
	outputLen := 32 * len(r.outputs)
	fmt.Fprintf(b, "        bytes memory output = new bytes(%d);\n", outputLen)
	b.WriteString("        bool success;\n        uint256 returned;\n")
	b.WriteString("        // Bound both the nested execution and copied return data.\n")
	b.WriteString("        assembly {\n")
	fmt.Fprintf(b, "            success := staticcall(%d, target, add(input, 32), mload(input), add(output, 32), %d)\n", RecordReadGas, outputLen)
	b.WriteString("            returned := returndatasize()\n        }\n")
	fmt.Fprintf(b, "        if (!success || returned != %d) return ARGUMENT_CONSTRAINT;\n", outputLen)
	b.WriteString("        bool found;\n")
	for i, output := range r.outputs {
		bits := recordOutputBits(output)
		isParty := slices.Contains(r.parties, i)
		if bits == 256 && !isParty {
			continue
		}
		b.WriteString("        {\n            uint256 word;\n")
		fmt.Fprintf(b, "            assembly { word := mload(add(output, %d)) }\n", 32+32*i)
		if bits < 256 {
			fmt.Fprintf(b, "            if (word >> %d != 0) return ARGUMENT_CONSTRAINT;\n", bits)
		}
		if isParty {
			b.WriteString("            if (word != 0) {\n                for (uint256 k = 0; k < linked.length; k++) {\n                    if (linked[k] == address(uint160(word))) { found = true; break; }\n                }\n            }\n")
		}
		b.WriteString("        }\n")
	}
	b.WriteString("        return found ? OK : ARGUMENT_CONSTRAINT;\n    }\n")
}
