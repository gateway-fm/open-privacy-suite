import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MethodPolicyManager } from "../MethodPolicyManager";
import { rbacApi } from "@/api/rbac";
import { getAdminToken } from "@/api/adminClient";

vi.mock("@/api/rbac", () => ({
  rbacApi: { contracts: { updateMethodPolicies: vi.fn() } },
}));
vi.mock("@/api/adminClient", () => ({ getAdminToken: vi.fn() }));

const paymentABI = JSON.stringify([
  { type: "function", name: "createPayment", stateMutability: "nonpayable",
    inputs: [{ name: "paymentIdentifier", type: "string" }, { name: "payee", type: "address" }, { name: "amount", type: "uint256" }], outputs: [] },
  { type: "function", name: "getPaymentInfo", stateMutability: "view",
    inputs: [{ name: "paymentIdentifier", type: "string" }],
    outputs: [{ name: "amount", type: "uint256" }, { name: "timestamp", type: "uint256" }, { name: "payer", type: "address" }, { name: "payee", type: "address" }, { name: "isCompleted", type: "bool" }] },
]);

const baseProps = { orgId: "org-1", contractAddress: "0xabc", contractAbi: paymentABI };

beforeEach(() => {
  vi.clearAllMocks();
  (getAdminToken as ReturnType<typeof vi.fn>).mockReturnValue("admin-tok");
});

describe("MethodPolicyManager", () => {
  it("shows the empty-state default and the surface-asymmetry warning", () => {
    render(<MethodPolicyManager {...baseProps} initialPolicy={null} />);
    expect(screen.getByText(/No method policies configured/i)).toBeInTheDocument();
    expect(screen.getByText(/not the record's event logs/i)).toBeInTheDocument();
  });

  it("C1: without an admin token, renders read-only (no configure button, no PUT)", () => {
    (getAdminToken as ReturnType<typeof vi.fn>).mockReturnValue("");
    render(<MethodPolicyManager {...baseProps} initialPolicy={null} />);
    expect(screen.queryByRole("button", { name: /configure a policy/i })).not.toBeInTheDocument();
    expect(screen.getByText(/requires the super-admin API token/i)).toBeInTheDocument();
    expect(rbacApi.contracts.updateMethodPolicies).not.toHaveBeenCalled();
  });

  it("drives the wizard and saves the Partior policy as the exact backend schema", async () => {
    const u = userEvent.setup();
    (rbacApi.contracts.updateMethodPolicies as ReturnType<typeof vi.fn>).mockResolvedValue({});
    render(<MethodPolicyManager {...baseProps} initialPolicy={null} />);

    await u.click(screen.getByRole("button", { name: /configure a policy/i }));
    await u.type(screen.getByLabelText("Record type name"), "payment");
    await u.selectOptions(screen.getByLabelText("Writer method"), "createPayment(string,address,uint256)");
    await u.selectOptions(screen.getByLabelText("Reader method"), "getPaymentInfo(string)");

    // capture field 0 → payer / sender / set_once (defaults)
    await u.type(screen.getByLabelText("capture field 0 name"), "payer");
    // add field 1 → payee / param 1
    await u.click(screen.getByRole("button", { name: "capture field", exact: true }));
    await u.type(screen.getByLabelText("capture field 1 name"), "payee");
    await u.selectOptions(screen.getByLabelText("capture field 1 source"), "param");
    await u.selectOptions(screen.getByLabelText("capture field 1 param index"), "1");
    // add field 2 → audience / visibleTo (merge auto-defaults to union)
    await u.click(screen.getByRole("button", { name: "capture field", exact: true }));
    await u.type(screen.getByLabelText("capture field 2 name"), "audience");
    await u.selectOptions(screen.getByLabelText("capture field 2 source"), "visibleTo");

    // allow: payer, payee, audience + return payer, payee
    await u.click(screen.getByLabelText("allow field payer"));
    await u.click(screen.getByLabelText("allow field payee"));
    await u.click(screen.getByLabelText("allow field audience"));
    await u.click(screen.getByLabelText("allow return payer"));
    await u.click(screen.getByLabelText("allow return payee"));

    await u.click(screen.getByRole("button", { name: /save policy/i }));

    await waitFor(() => expect(rbacApi.contracts.updateMethodPolicies).toHaveBeenCalledTimes(1));
    const [, , doc] = (rbacApi.contracts.updateMethodPolicies as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(doc).toEqual({
      records: {
        payment: {
          capture: [{
            method: "createPayment(string,address,uint256)",
            key: { source: "param", index: 0 },
            remember: {
              payer: { source: "sender", merge: "set_once" },
              payee: { source: "param", index: 1, merge: "set_once" },
              audience: { source: "visibleTo", merge: "union" },
            },
          }],
          access: [{
            method: "getPaymentInfo(string)",
            key: { source: "param", index: 0 },
            allow: [
              { callerIn: ["payer", "payee", "audience"] },
              { callerIn: { source: "return", paths: ["payer", "payee"], kind: "address" } },
            ],
            onNoRecord: "deny",
            else: "deny",
          }],
        },
      },
    });
  });

  it("surfaces a backend 400 validation message verbatim", async () => {
    const u = userEvent.setup();
    (rbacApi.contracts.updateMethodPolicies as ReturnType<typeof vi.fn>).mockRejectedValue({
      response: { status: 400, data: { error: "method policy failed ABI validation: key type \"address[]\" is not canonicalizable" } },
    });
    const policy = { records: { payment: { capture: [{ method: "createPayment(string,address,uint256)", key: { source: "param" as const, index: 0 }, remember: { payer: { source: "sender" as const, merge: "set_once" as const } } }], access: [{ method: "getPaymentInfo(string)", key: { source: "param" as const, index: 0 }, allow: [{ callerIn: ["payer"] }], onNoRecord: "deny" as const, else: "deny" as const }] } } };
    render(<MethodPolicyManager {...baseProps} initialPolicy={policy} />);
    // clear-confirm path is separate; here drive a fresh save via the wizard-less
    // Clear button which does call the API with null → but we want the 400 path.
    // Simplest: open wizard, it's pre-validated invalid until filled; instead we
    // assert the error surfacing through the Clear action.
    vi.stubGlobal("confirm", () => true);
    await u.click(screen.getByRole("button", { name: /clear policy/i }));
    await waitFor(() =>
      expect(screen.getByText(/not canonicalizable/i)).toBeInTheDocument()
    );
  });

  it("advanced JSON editor saves the full parsed document (multi-capture/reader)", async () => {
    const u = userEvent.setup();
    (rbacApi.contracts.updateMethodPolicies as ReturnType<typeof vi.fn>).mockResolvedValue({});
    render(<MethodPolicyManager {...baseProps} initialPolicy={null} />);

    await u.click(screen.getByRole("button", { name: /edit json/i }));
    const ta = screen.getByLabelText("Method policy JSON") as HTMLTextAreaElement;
    // A shape the guided wizard can't express: two capture specs on one record.
    const doc = {
      records: {
        payment: {
          capture: [
            { method: "createPayment(string,address,uint256)", key: { source: "param", index: 0 }, remember: { payer: { source: "sender", merge: "set_once" } } },
            { method: "completePayment(string)", key: { source: "param", index: 0 }, remember: { audience: { source: "visibleTo", merge: "union" } } },
          ],
          access: [
            { method: "getPaymentInfo(string)", key: { source: "param", index: 0 }, allow: [{ callerIn: ["payer", "audience"] }], onNoRecord: "deny", else: "deny" },
          ],
        },
      },
    };
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
    const ta = screen.getByLabelText("Method policy JSON");
    await u.clear(ta);
    await u.paste("{ not valid json");
    await u.click(screen.getByRole("button", { name: /save json/i }));
    expect(screen.getByText(/Invalid JSON/i)).toBeInTheDocument();
    expect(rbacApi.contracts.updateMethodPolicies).not.toHaveBeenCalled();
  });

  it("confirms before clearing (privacy-loosening)", async () => {
    const u = userEvent.setup();
    const confirmSpy = vi.fn(() => false); // user cancels
    vi.stubGlobal("confirm", confirmSpy);
    const policy = { records: { payment: { capture: [], access: [] } } };
    render(<MethodPolicyManager {...baseProps} initialPolicy={policy} />);
    await u.click(screen.getByRole("button", { name: /clear policy/i }));
    expect(confirmSpy).toHaveBeenCalled();
    expect(rbacApi.contracts.updateMethodPolicies).not.toHaveBeenCalled(); // cancelled
  });
});
