import { describe, it, expect } from "vitest";
import {
  parseAbiFunctions,
  parseAbiEvents,
  eventsWithKeyableParam,
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
  { type: "function", name: "processPayment", stateMutability: "nonpayable",
    inputs: [{ name: "paymentIdentifier", type: "string" }, { name: "status", type: "uint8" }], outputs: [] },
  { type: "function", name: "getPaymentInfo", stateMutability: "view",
    inputs: [{ name: "paymentIdentifier", type: "string" }],
    outputs: [{ name: "amount", type: "uint256" }, { name: "payer", type: "address" }, { name: "payee", type: "address" }] },
  // Event whose record key (paymentIdentifier) sits in the NON-indexed data —
  // the clean, recoverable path.
  { type: "event", name: "PaymentProcessed", anonymous: false,
    inputs: [{ name: "paymentIdentifier", type: "string", indexed: false }, { name: "status", type: "uint8", indexed: false }] },
  // Event with an INDEXED dynamic (string) key — its value is NOT recoverable
  // from the topic (only keccak256(value) is stored).
  { type: "event", name: "PaymentIndexed", anonymous: false,
    inputs: [{ name: "paymentIdentifier", type: "string", indexed: true }, { name: "amount", type: "uint256", indexed: false }] },
]);
const fns = parseAbiFunctions(paymentABI);
const events = parseAbiEvents(paymentABI);

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
  it("rejects a literal-shaped capture field name (final-audit HIGH)", () => {
    for (const name of ["0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC", "did:test:role"]) {
      const s = structuredClone(partior);
      s.records[0].captures[0].remember[0].field = name;
      expect(validateWizard(s, fns)).toMatch(/must not look like a DID\/address literal/);
    }
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
    expect(r.events).toEqual([]);
    expect(r.transactions).toEqual([]);
  });
});

// ---- RD-1206 event/transaction gating (additive) ----

describe("parseAbiEvents", () => {
  it("canonical event signatures (Go abi.Event.Sig form: no indexed keyword, no names)", () => {
    expect(events.map((e) => e.signature).sort()).toEqual([
      "PaymentIndexed(string,uint256)",
      "PaymentProcessed(string,uint8)",
    ]);
    const proc = events.find((e) => e.name === "PaymentProcessed")!;
    expect(proc.inputs).toEqual([
      { name: "paymentIdentifier", type: "string", indexed: false },
      { name: "status", type: "uint8", indexed: false },
    ]);
  });
  it("[] for garbage", () => {
    expect(parseAbiEvents("nope")).toEqual([]);
  });
  it("eventsWithKeyableParam drops an event whose only key is an indexed dynamic", () => {
    // PaymentIndexed's string key is indexed (unrecoverable) and uint256 amount
    // is fine, so it stays keyable via the amount param; PaymentProcessed stays
    // via its non-indexed string. Both remain, but PaymentIndexed's index-0
    // key is disabled in the picker (asserted via validation below).
    expect(eventsWithKeyableParam(events).map((e) => e.name).sort()).toEqual(["PaymentIndexed", "PaymentProcessed"]);
  });
});

// Full record: capture + access + one event + one transaction, all keyed on the
// same string paymentIdentifier, admitting the captured audience.
const partiorFull: WizardState = {
  records: [{
    recordType: "payment",
    captures: [
      { writerSig: "createPayment(string,address,uint256)", keyIndex: 0, remember: [
        { field: "payer", source: "sender", merge: "set_once" },
        { field: "audience", source: "visibleTo", merge: "union" },
      ]},
    ],
    readers: [{ readerSig: "getPaymentInfo(string)", keyIndex: 0, rules: [
      { kind: "callerIn", fields: ["payer", "audience"], principals: [], returnPaths: [], where: null },
    ]}],
    events: [
      { eventSig: "PaymentProcessed(string,uint8)", keyIndex: 0, rules: [
        { fields: ["audience"], principals: [], where: null },
      ]},
    ],
    transactions: [
      { methodSig: "processPayment(string,uint8)", keyIndex: 0, rules: [
        { fields: ["audience"], principals: [], where: null },
      ]},
    ],
  }],
};

describe("compileWizard — events + transactions", () => {
  it("emits the EXACT locked schema (deep-equal)", () => {
    const doc = compileWizard(partiorFull);
    expect(doc.records.payment.events).toEqual([
      { event: "PaymentProcessed(string,uint8)", key: { source: "eventParam", index: 0 }, allow: [{ callerIn: ["audience"] }] },
    ]);
    expect(doc.records.payment.transactions).toEqual([
      { method: "processPayment(string,uint8)", key: { source: "param", index: 0 }, allow: [{ callerIn: ["audience"] }] },
    ]);
  });

  it("omits events/transactions keys entirely when empty (matches Go omitempty)", () => {
    const s: WizardState = { records: [{
      recordType: "payment",
      captures: partiorFull.records[0].captures,
      readers: partiorFull.records[0].readers,
      events: [],
      transactions: [],
    }]};
    const rec = compileWizard(s).records.payment;
    expect("events" in rec).toBe(false);
    expect("transactions" in rec).toBe(false);
  });

  it("carries a literal principal + where into the audience allow rule", () => {
    const s = structuredClone(partiorFull);
    s.records[0].captures[0].remember.push({ field: "amount", source: "param", paramIndex: 2, merge: "set_once" });
    s.records[0].events[0].rules = [
      { fields: [], principals: ["did:test:compliance"], where: { field: "amount", op: "gte", value: "1000000" } },
    ];
    expect(compileWizard(s).records.payment.events![0].allow).toEqual([
      { callerIn: ["did:test:compliance"], where: { field: "amount", op: "gte", value: "1000000" } },
    ]);
  });
});

describe("decompileWizard round-trip — events + transactions", () => {
  it("compile → decompile → compile is stable", () => {
    const doc = compileWizard(partiorFull);
    const back = decompileWizard(doc);
    expect(compileWizard(back)).toEqual(doc);
  });
});

describe("validateWizard — events + transactions", () => {
  it("passes the full record", () => {
    expect(validateWizard(partiorFull, fns, events)).toBeNull();
  });

  it("rejects an event that is not in the ABI", () => {
    const s = structuredClone(partiorFull);
    s.records[0].events[0].eventSig = "GhostEvent(string)";
    expect(validateWizard(s, fns, events)).toMatch(/choose an event that exists in the ABI/);
  });

  it("rejects an event key whose type disagrees with the record key type", () => {
    const s = structuredClone(partiorFull);
    // point the event key at param 1 (uint8) — disagrees with the string record key.
    s.records[0].events[0].keyIndex = 1;
    expect(validateWizard(s, fns, events)).toMatch(/key types must match/);
  });

  it("rejects an indexed dynamic event key param (unrecoverable from a topic)", () => {
    const s = structuredClone(partiorFull);
    s.records[0].events[0].eventSig = "PaymentIndexed(string,uint256)";
    s.records[0].events[0].keyIndex = 0; // the indexed string
    expect(validateWizard(s, fns, events)).toMatch(/indexed string.*not recoverable from a log topic/);
  });

  it("rejects an event allow field that isn't a captured field", () => {
    const s = structuredClone(partiorFull);
    s.records[0].events[0].rules = [{ fields: ["ghost"], principals: [], where: null }];
    expect(validateWizard(s, fns, events)).toMatch(/allow field "ghost" is not a captured field/);
  });

  it("rejects a transaction method that is not in the ABI", () => {
    const s = structuredClone(partiorFull);
    s.records[0].transactions[0].methodSig = "ghostTx(string)";
    expect(validateWizard(s, fns, events)).toMatch(/choose a transaction method that exists in the ABI/);
  });

  it("rejects a transaction key whose type disagrees with the record key type", () => {
    const s = structuredClone(partiorFull);
    s.records[0].transactions[0].keyIndex = 1; // uint8 vs string
    expect(validateWizard(s, fns, events)).toMatch(/key types must match/);
  });

  it("rejects an event allow rule with no field and no principal", () => {
    const s = structuredClone(partiorFull);
    s.records[0].events[0].rules = [{ fields: [], principals: [], where: null }];
    expect(validateWizard(s, fns, events)).toMatch(/needs at least one captured field or literal principal/);
  });

  it("rejects a non-principal literal in a transaction allow rule", () => {
    const s = structuredClone(partiorFull);
    s.records[0].transactions[0].rules = [{ fields: [], principals: ["compliance-desk"], where: null }];
    expect(validateWizard(s, fns, events)).toMatch(/must be a did:/);
  });
});
