import { describe, it, expect } from "vitest";
import {
  parseAbiFunctions,
  compileMethodPolicy,
  validateWizard,
  isCanonicalizableKeyType,
  type WizardState,
} from "../methodPolicy";

const paymentABI = JSON.stringify([
  {
    type: "function",
    name: "createPayment",
    stateMutability: "nonpayable",
    inputs: [
      { name: "paymentIdentifier", type: "string" },
      { name: "payee", type: "address" },
      { name: "amount", type: "uint256" },
    ],
    outputs: [],
  },
  {
    type: "function",
    name: "getPaymentInfo",
    stateMutability: "view",
    inputs: [{ name: "paymentIdentifier", type: "string" }],
    outputs: [
      { name: "amount", type: "uint256" },
      { name: "timestamp", type: "uint256" },
      { name: "payer", type: "address" },
      { name: "payee", type: "address" },
      { name: "isCompleted", type: "bool" },
    ],
  },
]);

const partiorWizard: WizardState = {
  recordType: "payment",
  writerSig: "createPayment(string,address,uint256)",
  writerKeyIndex: 0,
  readerSig: "getPaymentInfo(string)",
  readerKeyIndex: 0,
  remember: [
    { field: "payer", source: "sender", merge: "set_once" },
    { field: "payee", source: "param", paramIndex: 1, merge: "set_once" },
    { field: "audience", source: "visibleTo", merge: "union" },
  ],
  allowFields: ["payer", "payee", "audience"],
  returnPaths: ["payer", "payee"],
};

describe("parseAbiFunctions", () => {
  it("produces canonical signatures and address outputs", () => {
    const fns = parseAbiFunctions(paymentABI);
    const get = fns.find((f) => f.name === "getPaymentInfo")!;
    expect(get.signature).toBe("getPaymentInfo(string)");
    expect(get.addressOutputs.map((o) => o.name)).toEqual(["payer", "payee"]);
    const create = fns.find((f) => f.name === "createPayment")!;
    expect(create.signature).toBe("createPayment(string,address,uint256)");
    expect(create.inputs[1]).toEqual({ name: "payee", type: "address" });
  });

  it("returns [] for missing/garbage ABI", () => {
    expect(parseAbiFunctions(undefined)).toEqual([]);
    expect(parseAbiFunctions("not json")).toEqual([]);
  });
});

describe("isCanonicalizableKeyType", () => {
  it("accepts scalar value types, rejects arrays/tuples", () => {
    for (const t of ["string", "address", "bytes32", "bytes", "uint256", "uint64", "bool"]) {
      expect(isCanonicalizableKeyType(t)).toBe(true);
    }
    for (const t of ["address[]", "tuple", "uint256[]", "string[]"]) {
      expect(isCanonicalizableKeyType(t)).toBe(false);
    }
  });
});

describe("compileMethodPolicy", () => {
  it("compiles the Partior policy to the exact backend schema", () => {
    const doc = compileMethodPolicy(partiorWizard);
    expect(doc).toEqual({
      records: {
        payment: {
          capture: [
            {
              method: "createPayment(string,address,uint256)",
              key: { source: "param", index: 0 },
              remember: {
                payer: { source: "sender", merge: "set_once" },
                payee: { source: "param", index: 1, merge: "set_once" },
                audience: { source: "visibleTo", merge: "union" },
              },
            },
          ],
          access: [
            {
              method: "getPaymentInfo(string)",
              key: { source: "param", index: 0 },
              allow: [
                { callerIn: ["payer", "payee", "audience"] },
                { callerIn: { source: "return", paths: ["payer", "payee"], kind: "address" } },
              ],
              onNoRecord: "deny",
              else: "deny",
            },
          ],
        },
      },
    });
  });

  it("merges into an existing document, preserving other record types", () => {
    const existing = { records: { other: { capture: [], access: [] } } };
    const doc = compileMethodPolicy(partiorWizard, existing);
    expect(Object.keys(doc.records).sort()).toEqual(["other", "payment"]);
  });

  it("omits the return rule when no return paths are chosen (capture-only)", () => {
    const doc = compileMethodPolicy({ ...partiorWizard, returnPaths: [] });
    const allow = doc.records.payment.access[0].allow;
    expect(allow).toHaveLength(1);
    expect(allow[0].callerIn).toEqual(["payer", "payee", "audience"]);
  });
});

describe("validateWizard", () => {
  const fns = parseAbiFunctions(paymentABI);
  it("passes the coherent Partior state", () => {
    expect(validateWizard(partiorWizard, fns)).toBeNull();
  });
  it("rejects a key-type mismatch between writer and reader", () => {
    // point the reader key at getPaymentInfo's only param (string) but the
    // writer key at the address param → mismatch
    const bad = { ...partiorWizard, writerKeyIndex: 1 };
    expect(validateWizard(bad, fns)).toMatch(/key types must match/);
  });
  it("requires at least one allow rule", () => {
    expect(validateWizard({ ...partiorWizard, allowFields: [], returnPaths: [] }, fns)).toMatch(/allow rule/);
  });
  it("requires a param index for param-sourced fields", () => {
    const bad = { ...partiorWizard, remember: [{ field: "payee", source: "param" as const, merge: "set_once" as const }] };
    expect(validateWizard(bad, fns)).toMatch(/pick which one/);
  });
  it("rejects an allow field that isn't captured", () => {
    expect(validateWizard({ ...partiorWizard, allowFields: ["ghost"] }, fns)).toMatch(/isn't a captured field/);
  });
});
