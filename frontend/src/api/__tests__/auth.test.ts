import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { http, HttpResponse } from 'msw';
import { server } from '@/test/mocks/server';
import {
  authApiMethods,
  ethLinkApiMethods,
  generatePrivadoLink,
  isMobileDevice,
  createAuthenticatedClient,
} from '../auth';
import {
  mockAuthRequest,
  mockTokenResponse,
  setSessionCompleted,
  setSessionFailed,
  resetSessionState,
} from '@/test/mocks/handlers';

describe('Auth API', () => {
  beforeEach(() => {
    resetSessionState();
  });

  describe('authApiMethods', () => {
    describe('requestAuth', () => {
      it('should request authentication and return session data', async () => {
        const response = await authApiMethods.requestAuth();

        expect(response.session_id).toBe(mockAuthRequest.session_id);
        expect(response.auth_request.id).toBe(mockAuthRequest.auth_request.id);
        expect(response.auth_request.body.callbackUrl).toBeDefined();
      });

      it('should handle request failure', async () => {
        server.use(
          http.post('/api/v1/auth/request', () => {
            return HttpResponse.json(
              { error: 'Service unavailable' },
              { status: 503 }
            );
          })
        );

        await expect(authApiMethods.requestAuth()).rejects.toThrow();
      });
    });

    describe('verifyAuth', () => {
      it('should verify auth with mock token in dev mode', async () => {
        const response = await authApiMethods.verifyAuth(
          'test-session',
          'mock.did:test:user'
        );

        expect(response.access_token).toBe(mockTokenResponse.access_token);
        expect(response.refresh_token).toBe(mockTokenResponse.refresh_token);
        expect(response.expires_in).toBe(mockTokenResponse.expires_in);
      });

      it('should reject invalid tokens', async () => {
        await expect(
          authApiMethods.verifyAuth('test-session', 'invalid-token')
        ).rejects.toThrow();
      });
    });

    describe('pollSession', () => {
      it('should return null when session is not complete', async () => {
        resetSessionState();
        const result = await authApiMethods.pollSession('test-session');
        expect(result).toBeNull();
      });

      // RD-1242: a rejected proof must be reported, not swallowed as "pending".
      it('should report a rejected proof with its curated reason', async () => {
        resetSessionState();
        setSessionFailed('verification_failed');

        const result = await authApiMethods.pollSession('test-session');

        expect(result).not.toBeNull();
        expect(result?.status).toBe('failed');
        expect(result?.status === 'failed' && result.reason).toBe('verification_failed');
      });

      it('should return tokens when session is complete', async () => {
        setSessionCompleted(true, mockTokenResponse);

        const result = await authApiMethods.pollSession('test-session');

        expect(result).not.toBeNull();
        expect(result?.status).toBe('completed');
        expect(result?.status === 'completed' && result.tokens.access_token).toBe(
          mockTokenResponse.access_token
        );
      });

      it('should handle poll errors gracefully', async () => {
        server.use(
          http.get('/api/v1/auth/session/:sessionId/status', () => {
            return HttpResponse.json(
              { error: 'Session not found' },
              { status: 404 }
            );
          })
        );

        const result = await authApiMethods.pollSession('nonexistent-session');
        expect(result).toBeNull();
      });
    });

    describe('refresh', () => {
      it('should refresh access token', async () => {
        const response = await authApiMethods.refresh('valid-refresh-token');

        expect(response.access_token).toBe('new-access-token');
        expect(response.refresh_token).toBe('new-refresh-token');
      });

      it('should handle refresh failure', async () => {
        server.use(
          http.post('/api/v1/refresh', () => {
            return HttpResponse.json(
              { error: 'Invalid refresh token' },
              { status: 401 }
            );
          })
        );

        await expect(
          authApiMethods.refresh('invalid-refresh-token')
        ).rejects.toThrow();
      });
    });

    describe('revoke', () => {
      it('should revoke refresh token', async () => {
        // Should not throw
        await expect(
          authApiMethods.revoke('valid-refresh-token')
        ).resolves.not.toThrow();
      });
    });
  });

  describe('ethLinkApiMethods', () => {
    const mockAccessToken = 'test-access-token';

    describe('getChallenge', () => {
      it('should get challenge message for signing', async () => {
        const response = await ethLinkApiMethods.getChallenge(mockAccessToken);

        expect(response.nonce).toBe('test-nonce-123');
        expect(response.message).toContain('Link Ethereum address to DID');
      });
    });

    describe('verifyLink', () => {
      it('should verify signature and link address', async () => {
        const response = await ethLinkApiMethods.verifyLink(
          mockAccessToken,
          'test-nonce',
          '0x1234567890123456789012345678901234567890',
          '0xsignature'
        );

        expect(response.message).toBe('Address linked successfully');
        expect(response.address).toBe(
          '0x1234567890123456789012345678901234567890'
        );
      });
    });

    describe('getAddresses', () => {
      it('should get linked addresses', async () => {
        const response = await ethLinkApiMethods.getAddresses(mockAccessToken);

        expect(response.addresses).toHaveLength(1);
        expect(response.addresses[0].address).toBe(
          '0x1234567890123456789012345678901234567890'
        );
      });
    });

    describe('unlinkAddress', () => {
      it('should unlink address', async () => {
        await expect(
          ethLinkApiMethods.unlinkAddress(
            mockAccessToken,
            '0x1234567890123456789012345678901234567890'
          )
        ).resolves.not.toThrow();
      });
    });
  });

  describe('createAuthenticatedClient', () => {
    it('should create axios client with authorization header', () => {
      const client = createAuthenticatedClient('test-token');

      expect(client.defaults.baseURL).toBe('/api/v1');
      expect(client.defaults.headers['Authorization']).toBe('Bearer test-token');
      expect(client.defaults.headers['Content-Type']).toBe('application/json');
    });
  });

  describe('generatePrivadoLink', () => {
    it('should generate valid iden3comm deep link', () => {
      const link = generatePrivadoLink(mockAuthRequest.auth_request);

      expect(link).toMatch(/^iden3comm:\/\/\?i_m=/);

      // Extract and decode the message
      const urlParams = new URLSearchParams(link.split('?')[1]);
      const encodedMessage = urlParams.get('i_m');
      expect(encodedMessage).not.toBeNull();

      const decodedMessage = atob(decodeURIComponent(encodedMessage!));
      const parsed = JSON.parse(decodedMessage);

      expect(parsed.id).toBe(mockAuthRequest.auth_request.id);
      expect(parsed.type).toBe(mockAuthRequest.auth_request.type);
    });

    it('should handle special characters in auth request', () => {
      const authRequestWithSpecialChars = {
        ...mockAuthRequest.auth_request,
        body: {
          ...mockAuthRequest.auth_request.body,
          reason: 'Test with special chars: é è ñ',
        },
      };

      const link = generatePrivadoLink(authRequestWithSpecialChars);
      expect(link).toMatch(/^iden3comm:\/\/\?i_m=/);
    });
  });

  describe('isMobileDevice', () => {
    const originalUserAgent = navigator.userAgent;

    afterEach(() => {
      Object.defineProperty(navigator, 'userAgent', {
        value: originalUserAgent,
        configurable: true,
      });
    });

    it('should return true for iPhone user agent', () => {
      Object.defineProperty(navigator, 'userAgent', {
        value:
          'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15',
        configurable: true,
      });

      expect(isMobileDevice()).toBe(true);
    });

    it('should return true for Android user agent', () => {
      Object.defineProperty(navigator, 'userAgent', {
        value:
          'Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 Chrome/90.0.4430.91',
        configurable: true,
      });

      expect(isMobileDevice()).toBe(true);
    });

    it('should return false for desktop user agent', () => {
      Object.defineProperty(navigator, 'userAgent', {
        value:
          'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/90.0.4430.93',
        configurable: true,
      });

      expect(isMobileDevice()).toBe(false);
    });
  });
});
