import { describe, it, expect } from "vitest";
import {
  parseAbiFunctions,
  compileWizard,
  decompileWizard,
  validateWizard,
  isCanonicalizableKeyType,
  emptyRecord,
  type WizardState,
} from "../methodPolicy";

const paymentABI = JSON.stringify([
  { type: "function", name: "createPayment", stateMutability: "nonpayable",
    inputs: [{ name: "paymentIdentifier", type: "string" }, { name: "payee", type: "address" }, { name: "amount", type: "uint256" }], outputs: [] },
  { type: "function", name: "completePayment", stateMutability: "nonpayable",
    inputs: [{ name: "paymentIdentifier", type: "string" }], outputs: [] },
  { type: "function", name: "getPaymentInfo", stateMutability: "view",
    inputs: [{ name: "paymentIdentifier", type: "string" }],
    outputs: [{ name: "amount", type: "uint256" }, { name: "payer", type: "address" }, { name: "payee", type: "address" }] },
]);
const fns = parseAbiFunctions(paymentABI);

// Full Partior record: two captures (create + complete) and one reader with a
// captured-field rule AND a return rule.
const partior: WizardState = {
  records: [{
    recordType: "payment",
    captures: [
      { writerSig: "createPayment(string,address,uint256)", keyIndex: 0, remember: [
        { field: "payer", source: "sender", merge: "set_once" },
        { field: "payee", source: "param", paramIndex: 1, merge: "set_once" },
        { field: "audience", source: "visibleTo", merge: "union" },
      ]},
      { writerSig: "completePayment(string)", keyIndex: 0, remember: [
        { field: "audience", source: "visibleTo", merge: "union" },
      ]},
    ],
    readers: [{ readerSig: "getPaymentInfo(string)", keyIndex: 0, rules: [
      { kind: "callerIn", fields: ["payer", "payee", "audience"], principals: [], returnPaths: [], where: null },
      { kind: "return", fields: [], principals: [], returnPaths: ["payer", "payee"] },
    ]}],
  }],
};

describe("parseAbiFunctions", () => {
  it("canonical signatures + address outputs", () => {
    const get = fns.find((f) => f.name === "getPaymentInfo")!;
    expect(get.signature).toBe("getPaymentInfo(string)");
    expect(get.addressOutputs.map((o) => o.name)).toEqual(["payer", "payee"]);
  });
  it("[] for garbage", () => {
    expect(parseAbiFunctions("nope")).toEqual([]);
  });
});

describe("isCanonicalizableKeyType", () => {
  it("scalars yes, arrays/tuples no", () => {
    for (const t of ["string", "address", "bytes32", "uint256", "uint64", "bool"]) expect(isCanonicalizableKeyType(t)).toBe(true);
    for (const t of ["address[]", "tuple", "uint256[]"]) expect(isCanonicalizableKeyType(t)).toBe(false);
  });
});

describe("compileWizard", () => {
  it("compiles the full Partior policy (2 captures, callerIn+return) to exact schema", () => {
    expect(compileWizard(partior)).toEqual({
      records: {
        payment: {
          capture: [
            { method: "createPayment(string,address,uint256)", key: { source: "param", index: 0 }, remember: {
              payer: { source: "sender", merge: "set_once" },
              payee: { source: "param", index: 1, merge: "set_once" },
              audience: { source: "visibleTo", merge: "union" },
            }},
            { method: "completePayment(string)", key: { source: "param", index: 0 }, remember: {
              audience: { source: "visibleTo", merge: "union" },
            }},
          ],
          access: [{
            method: "getPaymentInfo(string)", key: { source: "param", index: 0 },
            allow: [
              { callerIn: ["payer", "payee", "audience"] },
              { callerIn: { source: "return", paths: ["payer", "payee"], kind: "address" } },
            ],
            onNoRecord: "deny", else: "deny",
          }],
        },
      },
    });
  });

  it("Example 3: one writer mapped onto multiple readers", () => {
    const s: WizardState = { records: [{
      recordType: "invoice",
      captures: [{ writerSig: "createPayment(string,address,uint256)", keyIndex: 0, remember: [
        { field: "issuer", source: "sender", merge: "set_once" },
        { field: "debtor", source: "param", paramIndex: 1, merge: "set_once" },
      ]}],
      readers: [
        { readerSig: "getPaymentInfo(string)", keyIndex: 0, rules: [{ kind: "callerIn", fields: ["issuer", "debtor"], principals: [], returnPaths: [], where: null }] },
        { readerSig: "completePayment(string)", keyIndex: 0, rules: [{ kind: "callerIn", fields: ["issuer"], principals: [], returnPaths: [], where: null }] },
      ],
    }]};
    const doc = compileWizard(s);
    expect(doc.records.invoice.access).toHaveLength(2);
    expect(doc.records.invoice.access[0].method).toBe("getPaymentInfo(string)");
    expect(doc.records.invoice.access[1].method).toBe("completePayment(string)");
  });

  it("Example 4: where + literal principal", () => {
    const s: WizardState = { records: [{
      recordType: "payment",
      captures: [{ writerSig: "createPayment(string,address,uint256)", keyIndex: 0, remember: [
        { field: "payer", source: "sender", merge: "set_once" },
        { field: "amount", source: "param", paramIndex: 2, merge: "set_once" },
      ]}],
      readers: [{ readerSig: "getPaymentInfo(string)", keyIndex: 0, rules: [
        { kind: "callerIn", fields: ["payer"], principals: [], returnPaths: [], where: null },
        { kind: "callerIn", fields: [], principals: ["did:test:compliance"], returnPaths: [], where: { field: "amount", op: "gte", value: "1000000" } },
      ]}],
    }]};
    const allow = compileWizard(s).records.payment.access[0].allow;
    expect(allow[1]).toEqual({ callerIn: ["did:test:compliance"], where: { field: "amount", op: "gte", value: "1000000" } });
  });
});

describe("validateWizard", () => {
  it("passes the full Partior policy", () => {
    expect(validateWizard(partior, fns)).toBeNull();
  });
  it("rejects visibleTo + set_once", () => {
    const s = structuredClone(partior);
    // set BOTH captures' audience to set_once so the merge-consistency check
    // passes and the visibleTo⇒union invariant is the one that fires.
    s.records[0].captures[0].remember[2].merge = "set_once";
    s.records[0].captures[1].remember[0].merge = "set_once";
    expect(validateWizard(s, fns)).toMatch(/must use union/);
  });
  it("rejects conflicting merge for a re-used field across captures", () => {
    const s = structuredClone(partior);
    s.records[0].captures[1].remember[0].merge = "set_once"; // audience union in cap0, set_once in cap1
    expect(validateWizard(s, fns)).toMatch(/must use union|conflicting merge/);
  });
  it("rejects a callerIn field that isn't captured and isn't a principal", () => {
    const s = structuredClone(partior);
    s.records[0].readers[0].rules[0] = { kind: "callerIn", fields: ["ghost"], principals: [], returnPaths: [], where: null };
    expect(validateWizard(s, fns)).toMatch(/not a captured field/);
  });
  it("accepts a literal DID principal", () => {
    const s = structuredClone(partior);
    s.records[0].readers[0].rules[0] = { kind: "callerIn", fields: [], principals: ["did:test:compliance"], returnPaths: [], where: null };
    expect(validateWizard(s, fns)).toBeNull();
  });
  it("rejects a non-principal, non-field literal", () => {
    const s = structuredClone(partior);
    s.records[0].readers[0].rules[0] = { kind: "callerIn", fields: [], principals: ["compliance-desk"], returnPaths: [], where: null };
    expect(validateWizard(s, fns)).toMatch(/must be a did:/);
  });
  it("rejects duplicate record types", () => {
    const s: WizardState = { records: [partior.records[0], structuredClone(partior.records[0])] };
    expect(validateWizard(s, fns)).toMatch(/Duplicate record type/);
  });
  it("rejects where on a return rule", () => {
    const s = structuredClone(partior);
    s.records[0].readers[0].rules[1].where = { field: "payer", op: "eq", value: "x" };
    expect(validateWizard(s, fns)).toMatch(/where is not allowed on a return rule/);
  });
  it("rejects numeric where on a non-numeric field", () => {
    const s = structuredClone(partior);
    s.records[0].readers[0].rules[0].where = { field: "payer", op: "gte", value: "1" };
    expect(validateWizard(s, fns)).toMatch(/needs a numeric field/);
  });
  it("rejects a return path that isn't an address output", () => {
    const s = structuredClone(partior);
    s.records[0].readers[0].rules[1].returnPaths = ["amount"];
    expect(validateWizard(s, fns)).toMatch(/not an address output/);
  });
});

describe("decompileWizard round-trip", () => {
  it("compile → decompile → compile is stable for the Partior policy", () => {
    const doc = compileWizard(partior);
    const back = decompileWizard(doc);
    expect(compileWizard(back)).toEqual(doc);
  });
  it("empty doc → empty state", () => {
    expect(decompileWizard(null)).toEqual({ records: [] });
  });
});

describe("emptyRecord", () => {
  it("produces a minimal editable record", () => {
    const r = emptyRecord();
    expect(r.captures).toHaveLength(1);
    expect(r.readers).toHaveLength(1);
    expect(r.readers[0].rules).toHaveLength(1);
  });
});
