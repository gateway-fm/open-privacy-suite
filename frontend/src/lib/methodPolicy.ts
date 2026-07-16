// RD-1206 method-policy helpers: parse a contract ABI into the pieces the
// wizard/display need, and render a policy document in plain language.
//
// Canonical function signatures come from viem's toFunctionSignature, which
// produces the exact Solidity canonical form the Go backend uses
// (abi.Method.Sig) — including nested tuples — so a UI-built policy validates
// server-side on the first save.
import { toFunctionSignature, toEventSignature, type Abi, type AbiFunction, type AbiEvent } from "viem";
import type {
  MethodPolicyDocument,
  MethodPolicyAllowRule,
  MethodPolicyStringAllowRule,
  MethodPolicyWhere,
} from "@/types/rbac";

export interface AbiParam {
  name: string; // ABI name, or the positional index as a string when unnamed
  type: string;
}

export interface AbiFnInfo {
  name: string;
  signature: string; // canonical, matches the backend
  inputs: AbiParam[];
  outputs: AbiParam[];
  addressOutputs: AbiParam[]; // subset of outputs whose type is "address"
}

export interface AbiEventParam extends AbiParam {
  indexed: boolean;
}

export interface AbiEventInfo {
  name: string;
  signature: string; // canonical topic0 preimage, matches Go abi.Event.Sig
  inputs: AbiEventParam[];
}

// An ABI type that is dynamic (its indexed topic holds keccak256(value), not
// the value) and so cannot be recovered as a record key from a log topic.
const DYNAMIC_TYPE = /^(string|bytes)$/; // bytesN (fixed) is static and fine

export function isDynamicType(t: string): boolean {
  return DYNAMIC_TYPE.test(t);
}

// Types the backend can canonicalize as a record key (must match
// rbac.canonicalizableType): scalar value types only.
const CANONICALIZABLE_KEY = /^(string|address|bool|bytes\d*|bytes|u?int\d*)$/;

export function isCanonicalizableKeyType(t: string): boolean {
  return CANONICALIZABLE_KEY.test(t);
}

export function parseAbiFunctions(abiJSON?: string): AbiFnInfo[] {
  if (!abiJSON) return [];
  let abi: Abi;
  try {
    abi = JSON.parse(abiJSON) as Abi;
  } catch {
    return [];
  }
  const out: AbiFnInfo[] = [];
  for (const item of abi) {
    if (item.type !== "function") continue;
    const fn = item as AbiFunction;
    let signature: string;
    try {
      signature = toFunctionSignature(fn);
    } catch {
      continue;
    }
    const inputs = (fn.inputs ?? []).map((i, idx) => ({ name: i.name || String(idx), type: i.type }));
    const outputs = (fn.outputs ?? []).map((o, idx) => ({ name: o.name || String(idx), type: o.type }));
    out.push({
      name: fn.name,
      signature,
      inputs,
      outputs,
      addressOutputs: outputs.filter((o) => o.type === "address"),
    });
  }
  return out;
}

// Functions with at least one canonicalizable parameter can serve as writers
// or readers (they need a key parameter).
export function functionsWithKeyableParam(fns: AbiFnInfo[]): AbiFnInfo[] {
  return fns.filter((f) => f.inputs.some((p) => isCanonicalizableKeyType(p.type)));
}

// parseAbiEvents lists the contract's events with their canonical signatures.
// toEventSignature yields the exact `Name(t1,t2)` topic0-preimage form Go uses
// (abi.Event.Sig — no `indexed` keyword, no param names), so a UI-built events
// policy validates server-side on the first save.
export function parseAbiEvents(abiJSON?: string): AbiEventInfo[] {
  if (!abiJSON) return [];
  let abi: Abi;
  try {
    abi = JSON.parse(abiJSON) as Abi;
  } catch {
    return [];
  }
  const out: AbiEventInfo[] = [];
  for (const item of abi) {
    if (item.type !== "event") continue;
    const ev = item as AbiEvent;
    let signature: string;
    try {
      signature = toEventSignature(ev);
    } catch {
      continue;
    }
    out.push({
      name: ev.name,
      signature,
      inputs: (ev.inputs ?? []).map((i, idx) => ({
        name: i.name || String(idx),
        type: i.type,
        indexed: Boolean((i as { indexed?: boolean }).indexed),
      })),
    });
  }
  return out;
}

// Events with at least one recoverable (canonicalizable, and not an indexed
// dynamic) key parameter can be gated by a record key.
export function eventsWithKeyableParam(events: AbiEventInfo[]): AbiEventInfo[] {
  return events.filter((e) =>
    e.inputs.some((p) => isCanonicalizableKeyType(p.type) && !(p.indexed && isDynamicType(p.type)))
  );
}

// describeAllowRule renders one allow rule for the display.
export function describeAllowRule(rule: MethodPolicyAllowRule): string {
  let base: string;
  if (Array.isArray(rule.callerIn)) {
    base = `caller is one of: ${rule.callerIn.join(", ")}`;
  } else {
    base = `caller matches a returned address (${rule.callerIn.paths.join(", ")})`;
  }
  if (rule.where) {
    base += ` — and ${rule.where.field} ${rule.where.op} ${rule.where.value}`;
  }
  return base;
}

export interface RenderedRecord {
  recordType: string;
  readers: { method: string; keyParam: string; allows: string[] }[];
  captures: { method: string; keyParam: string; fields: string[] }[];
  events: { event: string; keyParam: string; allows: string[] }[];
  transactions: { method: string; keyParam: string; allows: string[] }[];
}

// describeStringAllowRule renders one callerIn-only rule (events/transactions).
export function describeStringAllowRule(rule: MethodPolicyStringAllowRule): string {
  let base = `caller is one of: ${(rule.callerIn ?? []).join(", ")}`;
  if (rule.where) base += ` — and ${rule.where.field} ${rule.where.op} ${rule.where.value}`;
  return base;
}

// ---- Structured wizard model (array-based; full schema) ----
//
// The wizard edits the WHOLE document: N record types, each with N capture specs
// and N reader specs, each reader with N allow rules. compileWizard() emits the
// exact backend schema; validateWizard() mirrors every backend invariant for
// instant feedback (the backend remains the source of truth).

export interface WizardRememberField {
  field: string;
  source: "sender" | "param" | "visibleTo";
  paramIndex?: number;
  merge: "set_once" | "union";
}

export interface WizardCapture {
  writerSig: string;
  keyIndex: number;
  remember: WizardRememberField[];
}

// An allow rule is EITHER a callerIn list (captured field names and/or literal
// DID/address principals) with an optional where, OR a return-address rule.
export interface WizardAllowRule {
  kind: "callerIn" | "return";
  fields: string[]; // captured field names (callerIn kind)
  principals: string[]; // literal did:/0x principals (callerIn kind)
  returnPaths: string[]; // reader address-output names (return kind)
  where?: { field: string; op: string; value: string } | null;
}

export interface WizardReader {
  readerSig: string;
  keyIndex: number;
  rules: WizardAllowRule[];
}

// An audience rule for events/transactions: captured-field / literal-principal
// membership with an optional where. There is NO return kind here (a log/tx has
// no return value), so this is the callerIn-only subset of WizardAllowRule.
export interface WizardAudienceRule {
  fields: string[]; // captured field names
  principals: string[]; // literal did:/0x principals
  where?: { field: string; op: string; value: string } | null;
}

// A gated event log. keyIndex is the index into the event's parameters.
export interface WizardEvent {
  eventSig: string;
  keyIndex: number;
  rules: WizardAudienceRule[];
}

// A gated writer transaction. keyIndex is the index into the writer's calldata.
export interface WizardTransaction {
  methodSig: string;
  keyIndex: number;
  rules: WizardAudienceRule[];
}

export interface WizardRecord {
  recordType: string;
  captures: WizardCapture[];
  readers: WizardReader[];
  // NEW — additive event/transaction gating (RD-1206). Optional so a legacy
  // capture/access-only record literal type-checks; emptyRecord/decompileWizard
  // always populate them (defaulted to [] on read for hand-built states).
  events?: WizardEvent[];
  transactions?: WizardTransaction[];
}

export interface WizardState {
  records: WizardRecord[];
}

export const WHERE_OPS = ["eq", "neq", "lt", "lte", "gt", "gte"] as const;
const NUMERIC_WHERE_OPS = new Set(["lt", "lte", "gt", "gte"]);

function isLiteralPrincipal(s: string): boolean {
  return (s.startsWith("did:") && s.length > 4) || /^0x[0-9a-fA-F]{40}$/.test(s);
}

function isNumericKind(kind: string): boolean {
  return kind.startsWith("uint") || kind.startsWith("int");
}

// declaredKinds computes, for one record, field name → kind ("did" or ABI type),
// or an error string if a name is re-declared with a conflicting kind/merge.
function declaredKinds(
  rec: WizardRecord,
  fns: AbiFnInfo[]
): { kinds: Map<string, string>; merges: Map<string, string>; err: string | null } {
  const kinds = new Map<string, string>();
  const merges = new Map<string, string>();
  for (const cap of rec.captures) {
    const writer = fns.find((f) => f.signature === cap.writerSig);
    if (!writer) continue;
    const seen = new Set<string>();
    for (const r of cap.remember) {
      const name = r.field.trim();
      if (!name) return { kinds, merges, err: "Every captured field needs a name." };
      // A capture field name must not look like a DID/address literal, or a
      // callerIn entry equal to it becomes ambiguous (captured field vs literal
      // principal) and can admit a caller with no captured basis.
      if (isLiteralPrincipal(name)) return { kinds, merges, err: `Field name "${name}" must not look like a DID/address literal.` };
      if (seen.has(name)) return { kinds, merges, err: `Duplicate field "${name}" within one capture.` };
      seen.add(name);
      let kind = "did";
      if (r.source === "param") {
        if (r.paramIndex == null || !writer.inputs[r.paramIndex]) {
          return { kinds, merges, err: `Field "${name}" is param-sourced — pick which parameter.` };
        }
        kind = writer.inputs[r.paramIndex].type;
      }
      const prevK = kinds.get(name);
      if (prevK && prevK !== kind) return { kinds, merges, err: `Field "${name}" has conflicting kinds across captures.` };
      const prevM = merges.get(name);
      if (prevM && prevM !== r.merge) return { kinds, merges, err: `Field "${name}" has conflicting merge modes across captures.` };
      kinds.set(name, kind);
      merges.set(name, r.merge);
    }
  }
  return { kinds, merges, err: null };
}

// validateAudienceRule checks one callerIn-only rule (events/transactions):
// captured-field / literal-principal membership with an optional where. Mirrors
// the callerIn branch of the reader validation. Returns null when valid.
function validateAudienceRule(
  rule: WizardAudienceRule,
  kinds: Map<string, string>,
  ctx: string
): string | null {
  if (rule.fields.length === 0 && rule.principals.length === 0) {
    return `${ctx}: an allow rule needs at least one captured field or literal principal.`;
  }
  for (const f of rule.fields) {
    if (!kinds.has(f)) return `${ctx}: allow field "${f}" is not a captured field.`;
  }
  for (const p of rule.principals) {
    if (!isLiteralPrincipal(p)) return `${ctx}: principal "${p}" must be a did:… or 0x… address.`;
  }
  if (rule.where) {
    const w = rule.where;
    if (!w.field) return `${ctx}: where.field is required.`;
    const k = kinds.get(w.field);
    if (!k) return `${ctx}: where.field "${w.field}" is not a captured field.`;
    if (!WHERE_OPS.includes(w.op as (typeof WHERE_OPS)[number])) return `${ctx}: where.op "${w.op}" is invalid.`;
    if (NUMERIC_WHERE_OPS.has(w.op)) {
      if (!isNumericKind(k)) return `${ctx}: where op ${w.op} needs a numeric field, but "${w.field}" is ${k}.`;
      if (!/^-?\d+$/.test(w.value.trim())) return `${ctx}: where.value "${w.value}" must be an integer for op ${w.op}.`;
    }
    if (!w.value && w.op !== "eq" && w.op !== "neq") return `${ctx}: where.value is required.`;
  }
  return null;
}

// validateWizard mirrors every backend invariant so the UI cannot Save a policy
// the backend would reject. Returns null when valid. `events` is the contract's
// parsed event list (needed to validate the events section); defaults to [] so
// legacy callers that only gate readers keep working.
export function validateWizard(s: WizardState, fns: AbiFnInfo[], events: AbiEventInfo[] = []): string | null {
  if (s.records.length === 0) return "Add at least one record type.";
  const recordNames = new Set<string>();
  for (const rec of s.records) {
    const rt = rec.recordType.trim();
    if (!rt) return "Every record needs a name.";
    if (recordNames.has(rt)) return `Duplicate record type "${rt}".`;
    recordNames.add(rt);
    if (rec.captures.length === 0) return `Record "${rt}": add at least one capture.`;
    if (rec.readers.length === 0) return `Record "${rt}": add at least one reader method to gate.`;

    // key type must agree across every capture + reader (and every gated
    // event/tx) of the record — this parity is what makes the log's decoded key
    // canonicalize to the exact record_key string that capture stored.
    let keyType = "";
    const checkKeyType = (t: string, sig: string, what: string): string | null => {
      if (keyType === "") keyType = t;
      else if (keyType !== t) return `Record "${rt}": key types must match across ${what} ${sig} (${t} vs ${keyType}).`;
      return null;
    };
    const checkKey = (sig: string, idx: number, what: string): string | null => {
      const fn = fns.find((f) => f.signature === sig);
      if (!fn) return `Record "${rt}": choose a ${what} method.`;
      const p = fn.inputs[idx];
      if (!p || !isCanonicalizableKeyType(p.type)) return `Record "${rt}": choose a valid record-key parameter on ${what} ${sig}.`;
      return checkKeyType(p.type, sig, what);
    };
    for (const cap of rec.captures) {
      const e = checkKey(cap.writerSig, cap.keyIndex, "writer");
      if (e) return e;
    }
    for (const rd of rec.readers) {
      const e = checkKey(rd.readerSig, rd.keyIndex, "reader");
      if (e) return e;
    }

    const { kinds, err } = declaredKinds(rec, fns);
    if (err) return `Record "${rt}": ${err}`;
    // visibleTo ⇒ union
    for (const cap of rec.captures) {
      for (const r of cap.remember) {
        if (r.source === "visibleTo" && r.merge === "set_once") {
          return `Record "${rt}": visibleTo field "${r.field}" must use union, not set_once.`;
        }
      }
    }

    for (const rd of rec.readers) {
      const reader = fns.find((f) => f.signature === rd.readerSig);
      if (!reader) return `Record "${rt}": choose a reader method.`;
      if (rd.rules.length === 0) return `Record "${rt}" reader ${rd.readerSig}: add at least one allow rule.`;
      const addrOuts = new Set(reader.addressOutputs.map((o) => o.name));
      for (const rule of rd.rules) {
        if (rule.kind === "return") {
          if (rule.returnPaths.length === 0) return `Record "${rt}": a return rule needs at least one address output.`;
          for (const p of rule.returnPaths) {
            if (!addrOuts.has(p)) return `Record "${rt}": return path "${p}" is not an address output of ${rd.readerSig}.`;
          }
          if (rule.where) return `Record "${rt}": where is not allowed on a return rule.`;
          continue;
        }
        // callerIn rule
        if (rule.fields.length === 0 && rule.principals.length === 0) {
          return `Record "${rt}": an allow rule needs at least one captured field or literal principal.`;
        }
        for (const f of rule.fields) {
          if (!kinds.has(f)) return `Record "${rt}": allow field "${f}" is not a captured field.`;
        }
        for (const p of rule.principals) {
          if (!isLiteralPrincipal(p)) return `Record "${rt}": principal "${p}" must be a did:… or 0x… address.`;
        }
        if (rule.where) {
          const w = rule.where;
          if (!w.field) return `Record "${rt}": where.field is required.`;
          const k = kinds.get(w.field);
          if (!k) return `Record "${rt}": where.field "${w.field}" is not a captured field.`;
          if (!WHERE_OPS.includes(w.op as (typeof WHERE_OPS)[number])) return `Record "${rt}": where.op "${w.op}" is invalid.`;
          if (NUMERIC_WHERE_OPS.has(w.op)) {
            if (!isNumericKind(k)) return `Record "${rt}": where op ${w.op} needs a numeric field, but "${w.field}" is ${k}.`;
            if (!/^-?\d+$/.test(w.value.trim())) return `Record "${rt}": where.value "${w.value}" must be an integer for op ${w.op}.`;
          }
          if (!w.value && w.op !== "eq" && w.op !== "neq") return `Record "${rt}": where.value is required.`;
        }
      }
    }

    // Events (additive gating). The event must exist in the ABI; the key param
    // index/type must be valid, must NOT be an indexed dynamic (unrecoverable
    // from a log topic), and must agree with the record's key type. Rules are
    // callerIn-only (no return, no where-on-return).
    for (const ev of rec.events ?? []) {
      const ctx = `Record "${rt}" event ${ev.eventSig || "?"}`;
      const info = events.find((e) => e.signature === ev.eventSig);
      if (!info) return `Record "${rt}": choose an event that exists in the ABI.`;
      const p = info.inputs[ev.keyIndex];
      if (!p || !isCanonicalizableKeyType(p.type)) return `${ctx}: choose a valid record-key parameter.`;
      if (p.indexed && isDynamicType(p.type)) {
        return `${ctx}: key parameter "${p.name}" is an indexed ${p.type} — its value is not recoverable from a log topic; use a non-indexed key.`;
      }
      const e = checkKeyType(p.type, ev.eventSig, "event");
      if (e) return e;
      if (ev.rules.length === 0) return `${ctx}: add at least one allow rule.`;
      for (const rule of ev.rules) {
        const re = validateAudienceRule(rule, kinds, ctx);
        if (re) return re;
      }
    }

    // Transactions (additive gating). The writer method must exist; the key
    // param index/type must be valid and agree with the record's key type.
    for (const tx of rec.transactions ?? []) {
      const ctx = `Record "${rt}" transaction ${tx.methodSig || "?"}`;
      const fn = fns.find((f) => f.signature === tx.methodSig);
      if (!fn) return `Record "${rt}": choose a transaction method that exists in the ABI.`;
      const p = fn.inputs[tx.keyIndex];
      if (!p || !isCanonicalizableKeyType(p.type)) return `${ctx}: choose a valid record-key parameter.`;
      const e = checkKeyType(p.type, tx.methodSig, "transaction");
      if (e) return e;
      if (tx.rules.length === 0) return `${ctx}: add at least one allow rule.`;
      for (const rule of tx.rules) {
        const re = validateAudienceRule(rule, kinds, ctx);
        if (re) return re;
      }
    }
  }
  return null;
}

// compileAudienceRules turns the callerIn-only wizard rules (events/tx) into the
// backend allow-rule array: a string callerIn (fields + principals) plus an
// optional where. There is no return form here.
function compileAudienceRules(rules: WizardAudienceRule[]): MethodPolicyStringAllowRule[] {
  return rules.map((rule) => {
    const entry: MethodPolicyStringAllowRule = { callerIn: [...rule.fields, ...rule.principals] };
    if (rule.where && rule.where.field) {
      entry.where = { field: rule.where.field, op: rule.where.op as MethodPolicyWhere["op"], value: rule.where.value };
    }
    return entry;
  });
}

// compileWizard emits the exact backend policy document from the wizard state.
export function compileWizard(s: WizardState): MethodPolicyDocument {
  const records: MethodPolicyDocument["records"] = {};
  for (const rec of s.records) {
    const capture = rec.captures.map((cap) => {
      const remember: Record<string, { source: "sender" | "param" | "visibleTo"; index?: number; merge: "set_once" | "union" }> = {};
      for (const r of cap.remember) {
        remember[r.field.trim()] =
          r.source === "param"
            ? { source: "param", index: r.paramIndex, merge: r.merge }
            : { source: r.source, merge: r.merge };
      }
      return { method: cap.writerSig, key: { source: "param" as const, index: cap.keyIndex }, remember };
    });
    const access = rec.readers.map((rd) => {
      const allow: MethodPolicyAllowRule[] = [];
      for (const rule of rd.rules) {
        if (rule.kind === "return") {
          allow.push({ callerIn: { source: "return", paths: [...rule.returnPaths], kind: "address" } });
        } else {
          const entry: MethodPolicyAllowRule = { callerIn: [...rule.fields, ...rule.principals] };
          if (rule.where && rule.where.field) {
            entry.where = { field: rule.where.field, op: rule.where.op as MethodPolicyWhere["op"], value: rule.where.value };
          }
          allow.push(entry);
        }
      }
      return { method: rd.readerSig, key: { source: "param" as const, index: rd.keyIndex }, allow, onNoRecord: "deny" as const, else: "deny" as const };
    });
    const out: MethodPolicyDocument["records"][string] = { capture, access };
    // Additive sections: omit the key entirely when there are no rules, so the
    // compiled document deep-equals the backend's `omitempty` marshaling.
    const evs = rec.events ?? [];
    if (evs.length > 0) {
      out.events = evs.map((ev) => ({
        event: ev.eventSig,
        key: { source: "eventParam" as const, index: ev.keyIndex },
        allow: compileAudienceRules(ev.rules),
      }));
    }
    const txs = rec.transactions ?? [];
    if (txs.length > 0) {
      out.transactions = txs.map((tx) => ({
        method: tx.methodSig,
        key: { source: "param" as const, index: tx.keyIndex },
        allow: compileAudienceRules(tx.rules),
      }));
    }
    records[rec.recordType.trim()] = out;
  }
  return { records };
}

// decompileWizard seeds the wizard from an existing policy document (for editing
// in place). Best-effort: returns a wizard state; anything the structured form
// can't represent 1:1 still round-trips through compile because the shapes match.
export function decompileWizard(doc: MethodPolicyDocument | null | undefined): WizardState {
  if (!doc || !doc.records) return { records: [] };
  const records: WizardRecord[] = [];
  for (const [recordType, rec] of Object.entries(doc.records)) {
    const captures: WizardCapture[] = (rec.capture ?? []).map((c) => ({
      writerSig: c.method,
      keyIndex: c.key.index,
      remember: Object.entries(c.remember ?? {}).map(([field, f]) => ({
        field,
        source: f.source,
        paramIndex: f.index,
        merge: f.merge,
      })),
    }));
    const readers: WizardReader[] = (rec.access ?? []).map((a) => ({
      readerSig: a.method,
      keyIndex: a.key.index,
      rules: (a.allow ?? []).map((r): WizardAllowRule => {
        if (Array.isArray(r.callerIn)) {
          const { fields, principals } = splitCallerIn(r.callerIn);
          return { kind: "callerIn", fields, principals, returnPaths: [], where: r.where ?? null };
        }
        return { kind: "return", fields: [], principals: [], returnPaths: [...r.callerIn.paths] };
      }),
    }));
    const events: WizardEvent[] = (rec.events ?? []).map((ev) => ({
      eventSig: ev.event,
      keyIndex: ev.key.index,
      rules: (ev.allow ?? []).map(decompileAudienceRule),
    }));
    const transactions: WizardTransaction[] = (rec.transactions ?? []).map((tx) => ({
      methodSig: tx.method,
      keyIndex: tx.key.index,
      rules: (tx.allow ?? []).map(decompileAudienceRule),
    }));
    records.push({ recordType, captures, readers, events, transactions });
  }
  return { records };
}

function splitCallerIn(callerIn: string[]): { fields: string[]; principals: string[] } {
  const fields: string[] = [];
  const principals: string[] = [];
  for (const c of callerIn) {
    if (isLiteralPrincipal(c)) principals.push(c);
    else fields.push(c);
  }
  return { fields, principals };
}

function decompileAudienceRule(r: MethodPolicyStringAllowRule): WizardAudienceRule {
  const { fields, principals } = splitCallerIn(r.callerIn ?? []);
  return { fields, principals, where: r.where ?? null };
}

// Factory helpers for the UI.
export function emptyAudienceRule(): WizardAudienceRule {
  return { fields: [], principals: [], where: null };
}

export function emptyEvent(): WizardEvent {
  return { eventSig: "", keyIndex: 0, rules: [emptyAudienceRule()] };
}

export function emptyTransaction(): WizardTransaction {
  return { methodSig: "", keyIndex: 0, rules: [emptyAudienceRule()] };
}

export function emptyRecord(): WizardRecord {
  return {
    recordType: "",
    captures: [{ writerSig: "", keyIndex: 0, remember: [{ field: "", source: "sender", merge: "set_once" }] }],
    readers: [{ readerSig: "", keyIndex: 0, rules: [{ kind: "callerIn", fields: [], principals: [], returnPaths: [], where: null }] }],
    events: [],
    transactions: [],
  };
}

// renderPolicy flattens a document into a display-friendly structure.
export function renderPolicy(doc: MethodPolicyDocument): RenderedRecord[] {
  const out: RenderedRecord[] = [];
  for (const [recordType, rec] of Object.entries(doc.records ?? {})) {
    out.push({
      recordType,
      readers: (rec.access ?? []).map((a) => ({
        method: a.method,
        keyParam: `param ${a.key.index}`,
        allows: (a.allow ?? []).map(describeAllowRule),
      })),
      captures: (rec.capture ?? []).map((c) => ({
        method: c.method,
        keyParam: `param ${c.key.index}`,
        fields: Object.entries(c.remember ?? {}).map(([name, f]) => {
          const src =
            f.source === "param" ? `param ${f.index}` : f.source;
          return `${name} = ${src} (${f.merge})`;
        }),
      })),
      events: (rec.events ?? []).map((e) => ({
        event: e.event,
        keyParam: `eventParam ${e.key.index}`,
        allows: (e.allow ?? []).map(describeStringAllowRule),
      })),
      transactions: (rec.transactions ?? []).map((t) => ({
        method: t.method,
        keyParam: `param ${t.key.index}`,
        allows: (t.allow ?? []).map(describeStringAllowRule),
      })),
    });
  }
  return out;
}
