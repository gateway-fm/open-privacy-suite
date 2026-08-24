import { describe, it, expect, beforeEach, vi } from 'vitest';
import { renderHook, render, waitFor, act } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import { server } from '@/test/mocks/server';

// Drive the token directly: these tests are about what the hook does when the
// identity behind the token changes mid-flight, which AuthContext's own
// refresh plumbing would only make harder to observe.
const mockAuth: { accessToken: string | null; isLoading: boolean } = {
  accessToken: 'token-admin',
  isLoading: false,
};

vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => mockAuth,
}));

const { useAdminStatus } = await import('../useAdminStatus');

describe('useAdminStatus', () => {
  beforeEach(() => {
    mockAuth.accessToken = 'token-admin';
    mockAuth.isLoading = false;
  });

  it('reports admin for a token the endpoint approves', async () => {
    server.use(
      http.get('/api/v1/me/admin-status', () => HttpResponse.json({ is_admin: true })),
    );

    const { result } = renderHook(() => useAdminStatus());

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.isAdmin).toBe(true);
  });

  it('does not keep the previous token answer while the next probe is in flight', async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => { release = r; });

    server.use(
      http.get('/api/v1/me/admin-status', async ({ request }) => {
        if (request.headers.get('Authorization') === 'Bearer token-admin') {
          return HttpResponse.json({ is_admin: true });
        }
        await gate;
        return HttpResponse.json({ is_admin: false });
      }),
    );

    const { result, rerender } = renderHook(() => useAdminStatus());
    await waitFor(() => expect(result.current.isAdmin).toBe(true));

    // Token rotates to a different identity; its answer has not arrived yet.
    mockAuth.accessToken = 'token-regular';
    rerender();

    // The previous identity's access must not be attributed to this one.
    await waitFor(() => expect(result.current.loading).toBe(true));
    expect(result.current.isAdmin).toBe(false);

    release();
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.isAdmin).toBe(false);
  });

  it('ignores a superseded probe that resolves after the token changed', async () => {
    let releaseAdmin!: () => void;
    const adminGate = new Promise<void>((r) => { releaseAdmin = r; });

    server.use(
      http.get('/api/v1/me/admin-status', async ({ request }) => {
        if (request.headers.get('Authorization') === 'Bearer token-admin') {
          await adminGate;
          return HttpResponse.json({ is_admin: true });
        }
        return HttpResponse.json({ is_admin: false });
      }),
    );

    const { result, rerender } = renderHook(() => useAdminStatus());

    // Swap to the non-admin token while the admin probe is still open.
    mockAuth.accessToken = 'token-regular';
    rerender();
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.isAdmin).toBe(false);

    // The stale admin answer now lands. It must not restore admin UI.
    await act(async () => {
      releaseAdmin();
      await new Promise((r) => setTimeout(r, 20));
    });
    expect(result.current.isAdmin).toBe(false);
  });

  it('ignores a probe whose body parses after the token changed', async () => {
    // Narrower window than the test above: the response itself arrives while
    // the probe is still current, and only body parsing straddles the token
    // change. msw cannot stage that — the fetch has to be stubbed so json()
    // is a promise the test controls.
    let releaseBody!: () => void;
    const bodyGate = new Promise<void>((r) => { releaseBody = r; });
    // Signals that the hook is actually parked inside json(). Without waiting
    // for it the token can rotate before the fetch continuation runs, and the
    // earlier cancellation check swallows the probe — leaving this window
    // untested.
    let bodyRequested!: () => void;
    const insideJson = new Promise<void>((r) => { bodyRequested = r; });

    const fetchStub = vi.spyOn(globalThis, 'fetch').mockImplementation((_url, init) => {
      const auth = (init?.headers as Record<string, string>)?.Authorization;
      if (auth === 'Bearer token-admin') {
        // Response resolves immediately; the BODY is what lags.
        return Promise.resolve({
          ok: true,
          json: () => { bodyRequested(); return bodyGate.then(() => ({ is_admin: true })); },
        } as unknown as Response);
      }
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ is_admin: false }),
      } as unknown as Response);
    });

    try {
      const { result, rerender } = renderHook(() => useAdminStatus());
      await insideJson;

      mockAuth.accessToken = 'token-regular';
      rerender();
      await waitFor(() => expect(result.current.loading).toBe(false));
      expect(result.current.isAdmin).toBe(false);

      await act(async () => {
        releaseBody();
        await new Promise((r) => setTimeout(r, 20));
      });
      expect(result.current.isAdmin).toBe(false);
    } finally {
      fetchStub.mockRestore();
    }
  });

  it('reports not-admin with no token, without probing', async () => {
    mockAuth.accessToken = null;

    const { result } = renderHook(() => useAdminStatus());

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.isAdmin).toBe(false);
  });

  // Companion to the RequireAdmin render-phase test, and it has to use the
  // same trick for the same reason: renderHook's rerender() runs inside act(),
  // which flushes the re-arming effect before result.current can be read, so
  // the offending commit is invisible to a post-rerender assertion. Recording
  // the value *during* render is what exposes it.
  it('never reports a stale answer to a render under the new token', async () => {
    const seen: Array<{ token: string | null; isAdmin: boolean; loading: boolean }> = [];

    function Probe() {
      const { isAdmin, loading } = useAdminStatus();
      seen.push({ token: mockAuth.accessToken, isAdmin, loading });
      return null;
    }

    let release!: () => void;
    const gate = new Promise<void>((r) => { release = r; });

    server.use(
      http.get('/api/v1/me/admin-status', async ({ request }) => {
        if (request.headers.get('Authorization') === 'Bearer token-admin') {
          return HttpResponse.json({ is_admin: true });
        }
        await gate;
        return HttpResponse.json({ is_admin: false });
      }),
    );

    // A fresh element each time — an identical element lets React bail out of
    // the re-render, which would make this test pass without proving anything.
    const tree = () => <Probe />;
    const { rerender } = render(tree());
    await waitFor(() => expect(seen.some((e) => e.isAdmin && !e.loading)).toBe(true));

    mockAuth.accessToken = 'token-regular';
    rerender(tree());

    // No render under token-regular may have been handed the admin answer that
    // belongs to token-admin.
    expect(seen.filter((e) => e.token === 'token-regular' && e.isAdmin)).toEqual([]);

    release();
    await waitFor(() => expect(seen[seen.length - 1].loading).toBe(false));
    expect(seen.filter((e) => e.token === 'token-regular' && e.isAdmin)).toEqual([]);
  });
});
