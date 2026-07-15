import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MethodPolicyManager } from "../MethodPolicyManager";
import { rbacApi } from "@/api/rbac";

vi.mock("@/api/rbac", () => ({
  rbacApi: { contracts: { updateMethodPolicies: vi.fn(), simulateMethodPolicy: vi.fn() } },
}));

const paymentABI = JSON.stringify([
  { type: "function", name: "createPayment", stateMutability: "nonpayable",
    inputs: [{ name: "paymentIdentifier", type: "string" }, { name: "payee", type: "address" }, { name: "amount", type: "uint256" }], outputs: [] },
  { type: "function", name: "getPaymentInfo", stateMutability: "view",
    inputs: [{ name: "paymentIdentifier", type: "string" }],
    outputs: [{ name: "amount", type: "uint256" }, { name: "payer", type: "address" }, { name: "payee", type: "address" }] },
]);
const baseProps = { orgId: "org-1", contractAddress: "0xabc", contractAbi: paymentABI };

beforeEach(() => {
  vi.clearAllMocks();
});

describe("MethodPolicyManager", () => {
  it("empty state + getter-only caveat", () => {
    render(<MethodPolicyManager {...baseProps} initialPolicy={null} />);
    expect(screen.getByText(/No method policies configured/i)).toBeInTheDocument();
    expect(screen.getByText(/not the record's event logs/i)).toBeInTheDocument();
  });

  it("C1: read-only admin → read-only (no configure, no PUT)", () => {
    // Tier-2 org-admin control: a non-read-only admin can configure (covered by
    // the save tests below); a read-only admin sees the panel read-only.
    render(<MethodPolicyManager {...baseProps} initialPolicy={null} isReadonlyAdmin />);
    expect(screen.queryByRole("button", { name: /configure a policy/i })).not.toBeInTheDocument();
    expect(screen.getByText(/requires org-admin \(non-read-only\) access/i)).toBeInTheDocument();
    expect(rbacApi.contracts.updateMethodPolicies).not.toHaveBeenCalled();
  });

  it("structured editor builds and saves a capture+reader policy in exact schema", async () => {
    const u = userEvent.setup();
    (rbacApi.contracts.updateMethodPolicies as ReturnType<typeof vi.fn>).mockResolvedValue({});
    render(<MethodPolicyManager {...baseProps} initialPolicy={null} />);

    await u.click(screen.getByRole("button", { name: /configure a policy/i }));
    const editor = screen.getByTestId("method-policy-structured");
    await u.type(within(editor).getByLabelText("record type name"), "payment");
    await u.selectOptions(within(editor).getByLabelText("writer method"), "createPayment(string,address,uint256)");
    // capture field 0 → payer / sender / set_once (defaults)
    await u.type(within(editor).getByLabelText("capture field 0 name"), "payer");
    await u.selectOptions(within(editor).getByLabelText("reader method"), "getPaymentInfo(string)");
    // allow rule: tick the captured field "payer"
    await u.click(within(editor).getByLabelText("allow field payer"));

    await u.click(screen.getByRole("button", { name: /save policy/i }));
    await waitFor(() => expect(rbacApi.contracts.updateMethodPolicies).toHaveBeenCalledTimes(1));
    const [, , doc] = (rbacApi.contracts.updateMethodPolicies as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(doc).toEqual({
      records: {
        payment: {
          capture: [{ method: "createPayment(string,address,uint256)", key: { source: "param", index: 0 }, remember: { payer: { source: "sender", merge: "set_once" } } }],
          access: [{ method: "getPaymentInfo(string)", key: { source: "param", index: 0 }, allow: [{ callerIn: ["payer"] }], onNoRecord: "deny", else: "deny" }],
        },
      },
    });
  });

  it("surfaces a backend 400 verbatim (via clear path)", async () => {
    const u = userEvent.setup();
    (rbacApi.contracts.updateMethodPolicies as ReturnType<typeof vi.fn>).mockRejectedValue({
      response: { status: 400, data: { error: "method policy failed ABI validation: nope" } },
    });
    vi.stubGlobal("confirm", () => true);
    render(<MethodPolicyManager {...baseProps} initialPolicy={{ records: { payment: { capture: [], access: [] } } }} />);
    await u.click(screen.getByRole("button", { name: /clear policy/i }));
    await waitFor(() => expect(screen.getByText(/nope/i)).toBeInTheDocument());
  });

  it("confirms before clearing", async () => {
    const u = userEvent.setup();
    const confirmSpy = vi.fn(() => false);
    vi.stubGlobal("confirm", confirmSpy);
    render(<MethodPolicyManager {...baseProps} initialPolicy={{ records: { payment: { capture: [], access: [] } } }} />);
    await u.click(screen.getByRole("button", { name: /clear policy/i }));
    expect(confirmSpy).toHaveBeenCalled();
    expect(rbacApi.contracts.updateMethodPolicies).not.toHaveBeenCalled();
  });

  it("advanced JSON editor saves the full parsed document", async () => {
    const u = userEvent.setup();
    (rbacApi.contracts.updateMethodPolicies as ReturnType<typeof vi.fn>).mockResolvedValue({});
    render(<MethodPolicyManager {...baseProps} initialPolicy={null} />);
    await u.click(screen.getByRole("button", { name: /edit json/i }));
    const ta = screen.getByLabelText("Method policy JSON");
    const doc = { records: { payment: { capture: [{ method: "createPayment(string,address,uint256)", key: { source: "param", index: 0 }, remember: { payer: { source: "sender", merge: "set_once" } } }], access: [{ method: "getPaymentInfo(string)", key: { source: "param", index: 0 }, allow: [{ callerIn: ["payer"] }], onNoRecord: "deny", else: "deny" }] } } };
    await u.clear(ta);
    await u.paste(JSON.stringify(doc));
    await u.click(screen.getByRole("button", { name: /save json/i }));
    await waitFor(() => expect(rbacApi.contracts.updateMethodPolicies).toHaveBeenCalledTimes(1));
    const [, , saved] = (rbacApi.contracts.updateMethodPolicies as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(saved).toEqual(doc);
  });

  it("advanced JSON editor rejects invalid JSON without calling the API", async () => {
    const u = userEvent.setup();
    render(<MethodPolicyManager {...baseProps} initialPolicy={null} />);
    await u.click(screen.getByRole("button", { name: /edit json/i }));
    await u.clear(screen.getByLabelText("Method policy JSON"));
    await u.paste("{ not json");
    await u.click(screen.getByRole("button", { name: /save json/i }));
    expect(screen.getByText(/Invalid JSON/i)).toBeInTheDocument();
    expect(rbacApi.contracts.updateMethodPolicies).not.toHaveBeenCalled();
  });

  it("simulator runs and renders the result + admit-set", async () => {
    const u = userEvent.setup();
    (rbacApi.contracts.simulateMethodPolicy as ReturnType<typeof vi.fn>).mockResolvedValue({
      data: { result: "allow", record_type: "payment", matched_rule: "captured:payer", has_return_source: false, poisoned: false, captured: { payer: ["did:test:alice"] } },
    });
    render(<MethodPolicyManager {...baseProps} initialPolicy={{ records: { payment: { capture: [], access: [] } } }} />);
    await u.click(screen.getByRole("button", { name: /simulate/i }));
    const panel = screen.getByTestId("method-policy-simulate");
    await u.selectOptions(within(panel).getByLabelText("simulate method"), "getPaymentInfo(string)");
    await u.type(within(panel).getByLabelText("simulate record key"), "PAY-1");
    await u.type(within(panel).getByLabelText("simulate caller did"), "did:test:alice");
    await u.click(within(panel).getByRole("button", { name: /^simulate$/i }));
    await waitFor(() => expect(rbacApi.contracts.simulateMethodPolicy).toHaveBeenCalledTimes(1));
    expect(within(panel).getByText("allow")).toBeInTheDocument();
    expect(within(panel).getByText(/did:test:alice/)).toBeInTheDocument();
  });
});
