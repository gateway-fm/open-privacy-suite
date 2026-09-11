import type { ExecutionPolicyContext, PolicyDocument } from '@/types/executionPolicy';

/**
 * Shape of an error response from the admin API. Every handler answers a
 * refusal with `{ "error": "..." }`.
 */
export interface ApiErrorShape {
  status?: number;
  /** The server's message, shown verbatim — it names the field at fault. */
  message: string;
}

/**
 * extractApiError pulls the server's own message out of an axios failure.
 *
 * Policy validation messages are the main authoring aid: they name the field
 * at fault and nothing else. They are shown exactly as the server wrote them,
 * never summarised, so `fallback` is used only when there is no message at all
 * (a network failure, or a response that carried no body).
 */
export function extractApiError(err: unknown, fallback: string): ApiErrorShape {
  const axiosError = err as {
    response?: { status?: number; data?: { error?: string } };
  };
  return {
    status: axiosError.response?.status,
    message: axiosError.response?.data?.error?.trim() || fallback,
  };
}

/**
 * buildPolicySkeleton returns a minimal valid candidate for this organization:
 * the schema version, kind, org and nested-call semantic the backend reported,
 * plus an empty bindings list.
 *
 * An empty `bindings` list denies everything, which is the fail-closed
 * starting point — the author adds rules to it, never removes a default.
 */
export function buildPolicySkeleton(context: ExecutionPolicyContext): string {
  const skeleton: PolicyDocument = {
    apiVersion: context.api_version,
    kind: context.kind,
    org: context.org_id,
    nestedCalls: context.nested_calls,
    bindings: [],
  };
  return `${JSON.stringify(skeleton, null, 2)}\n`;
}

/**
 * shortDigest abbreviates a digest for a table cell. The full value stays
 * available in a title attribute so a reviewer can still compare it by eye.
 */
export function shortDigest(digest: string, length = 12): string {
  if (!digest) return '—';
  return digest.length <= length ? digest : `${digest.slice(0, length)}…`;
}

/** Formats an RFC3339 timestamp for display, tolerating an absent value. */
export function formatPolicyTimestamp(value?: string): string {
  if (!value) return '—';
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

/**
 * splitAddressList turns a free-text list of addresses (comma, whitespace or
 * newline separated) into the array the simulate route expects.
 */
export function splitAddressList(value: string): string[] {
  return value
    .split(/[\s,]+/)
    .map(entry => entry.trim())
    .filter(entry => entry.length > 0);
}
