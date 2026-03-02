import axios from 'axios';

// Auth API client - uses /api/v1 prefix for versioned API
const authApi = axios.create({
  baseURL: '/api/v1',
  headers: {
    'Content-Type': 'application/json',
  },
});

export interface AuthRequestResponse {
  session_id: string;
  auth_request: {
    id: string;
    typ: string;
    type: string;
    body: {
      callbackUrl: string;
      reason: string;
      scope?: unknown[];
    };
    from: string;
  };
}

export interface AuthTokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

export interface HumanityVerificationError {
  error: 'humanity_verification_required';
  message: string;
  verify_url: string;
}

export interface EthLinkChallengeResponse {
  nonce: string;
  message: string;
}

export interface EthAddressResponse {
  address: string;
  verified_at: string;
  ens_name?: string;
  ens_resolved_at?: string;
}

export interface EthAddressesResponse {
  addresses: EthAddressResponse[];
}

// Create authenticated API client
export function createAuthenticatedClient(accessToken: string) {
  return axios.create({
    baseURL: '/api/v1',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${accessToken}`,
    },
  });
}

export const authApiMethods = {
  // Step 1: Request auth challenge (returns QR code data)
  requestAuth: async (): Promise<AuthRequestResponse> => {
    // Pass the browser origin so the backend can construct the correct callback URL
    // This is more reliable than relying on X-Forwarded-Host headers
    const response = await authApi.post<AuthRequestResponse>('/auth/request', {
      callback_origin: window.location.origin,
    });
    return response.data;
  },

  // Step 2: Verify proof (development only - wallet usually calls callback directly)
  verifyAuth: async (sessionId: string, jwzToken: string): Promise<AuthTokenResponse> => {
    const response = await authApi.post<AuthTokenResponse>('/auth/verify', {
      session_id: sessionId,
      jwz_token: jwzToken,
    });
    return response.data;
  },

  // Poll for session completion (check if wallet has completed auth)
  pollSession: async (sessionId: string): Promise<AuthTokenResponse | null> => {
    try {
      // In a real implementation, you'd have a dedicated endpoint for this
      // For now, we'll poll the callback status
      const response = await authApi.get(`/auth/session/${sessionId}/status`);
      if (response.data.completed) {
        return response.data.tokens;
      }
      return null;
    } catch (err) {
      // Re-throw humanity verification errors so they can be handled by the caller
      if (axios.isAxiosError(err) && err.response?.data?.error === 'humanity_verification_required') {
        throw err;
      }
      // Swallow other errors (e.g., 404 for pending session)
      return null;
    }
  },

  // Refresh access token
  refresh: async (refreshToken: string): Promise<AuthTokenResponse> => {
    const response = await authApi.post<AuthTokenResponse>('/refresh', {
      refresh_token: refreshToken,
    });
    return response.data;
  },

  // Revoke tokens - always revokes refresh token, optionally revokes access token
  // Revoking access token ensures immediate invalidation (vs waiting for 30 min expiry)
  revoke: async (refreshToken: string, accessToken?: string): Promise<void> => {
    await authApi.post('/revoke', {
      refresh_token: refreshToken,
      ...(accessToken && { access_token: accessToken }),
    });
  },

  // Get available authentication providers
  getAuthProviders: async (): Promise<AuthProvidersResponse> => {
    const response = await authApi.get<AuthProvidersResponse>('/auth/providers');
    return response.data;
  },

  // Get Microsoft authorization URL for Azure AD login
  getAzureAuthURL: async (redirectURI: string): Promise<AzureAuthURLResponse> => {
    const response = await authApi.get<AzureAuthURLResponse>('/auth/azure/url', {
      params: { redirect_uri: redirectURI },
    });
    return response.data;
  },

  // Exchange Azure AD authorization code for our JWT tokens
  completeAzureLogin: async (
    code: string,
    state: string,
    redirectURI: string
  ): Promise<AuthTokenResponse> => {
    const response = await authApi.post<AuthTokenResponse>('/auth/azure/callback', {
      code,
      state,
      redirect_uri: redirectURI,
    });
    return response.data;
  },
};

export const ethLinkApiMethods = {
  // Get challenge message to sign
  getChallenge: async (accessToken: string): Promise<EthLinkChallengeResponse> => {
    const client = createAuthenticatedClient(accessToken);
    const response = await client.post<EthLinkChallengeResponse>('/eth/link/challenge');
    return response.data;
  },

  // Verify signature and link address
  verifyLink: async (
    accessToken: string,
    nonce: string,
    address: string,
    signature: string
  ): Promise<{ message: string; address: string }> => {
    const client = createAuthenticatedClient(accessToken);
    const response = await client.post('/eth/link/verify', {
      nonce,
      address,
      signature,
    });
    return response.data;
  },

  // Get linked addresses
  getAddresses: async (accessToken: string): Promise<EthAddressesResponse> => {
    const client = createAuthenticatedClient(accessToken);
    const response = await client.get<EthAddressesResponse>('/eth/addresses');
    return response.data;
  },

  // Unlink address
  unlinkAddress: async (accessToken: string, address: string): Promise<void> => {
    const client = createAuthenticatedClient(accessToken);
    await client.delete(`/eth/addresses/${address}`);
  },

  // Refresh ENS name for an address
  refreshEns: async (
    accessToken: string,
    address: string
  ): Promise<{ address: string; ens_name: string | null }> => {
    const client = createAuthenticatedClient(accessToken);
    const response = await client.post(`/eth/addresses/${address}/refresh-ens`);
    return response.data;
  },
};

// Generate Privado ID deep link / universal link
export function generatePrivadoLink(authRequest: AuthRequestResponse['auth_request']): string {
  // Privado ID uses iden3comm protocol
  // Format: iden3comm://?i_m=<base64_encoded_message>
  const message = JSON.stringify(authRequest);
  const encoded = btoa(message);
  return `iden3comm://?i_m=${encodeURIComponent(encoded)}`;
}

// Check if we're on mobile
export function isMobileDevice(): boolean {
  return /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(
    navigator.userAgent
  );
}

export interface AuthProvidersResponse {
  providers: string[];
}

export interface AzureAuthURLResponse {
  url: string;
  state: string;
}

// User organization info
export interface UserOrg {
  id: string;
  slug: string;
  name: string;
}

export interface UserOrgsResponse {
  organizations: UserOrg[];
}

export const userApiMethods = {
  // Get user's organizations
  getMyOrganizations: async (accessToken: string): Promise<UserOrgsResponse> => {
    const client = createAuthenticatedClient(accessToken);
    const response = await client.get<UserOrgsResponse>('/me/orgs');
    return response.data;
  },
};
