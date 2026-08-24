import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { server } from '@/test/mocks/server';
import OnboardByDIDForm from '../OnboardByDIDForm';
import { mockGroup, mockChildGroup } from '@/test/mocks/handlers';

// A plausible DID — long enough to pass the local validator and in the
// shape the backend accepts.
const VALID_DID = 'did:iden3:privado:main:2qABCDeFgHiJkLmNoPqRsTuVwXyZ1234567890aBcDeFgHi';

function renderForm(
  props: Partial<React.ComponentProps<typeof OnboardByDIDForm>> = {}
) {
  const defaultProps: React.ComponentProps<typeof OnboardByDIDForm> = {
    orgId: 'org-1',
    groups: [mockGroup, mockChildGroup],
    onClose: vi.fn(),
    onSave: vi.fn(),
  };
  return render(<OnboardByDIDForm {...defaultProps} {...props} />);
}

async function selectGroup(
  user: ReturnType<typeof userEvent.setup>,
  optionPattern: RegExp
) {
  const combobox = screen.getByRole('combobox');
  await user.click(combobox);
  await waitFor(() => {
    expect(screen.getByRole('option', { name: optionPattern })).toBeInTheDocument();
  });
  await user.click(screen.getByRole('option', { name: optionPattern }));
}

describe('OnboardByDIDForm', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Form rendering', () => {
    it('renders DID input, group select, and onboard button', () => {
      renderForm();

      expect(screen.getByLabelText(/User DID/i)).toBeInTheDocument();
      expect(screen.getByText('Group')).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /Onboard user/i })).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /Cancel/i })).toBeInTheDocument();
    });

    it('renders provided groups in the dropdown', async () => {
      const user = userEvent.setup();
      renderForm();

      await user.click(screen.getByRole('combobox'));

      await waitFor(() => {
        expect(screen.getByRole('option', { name: /Root Group/i })).toBeInTheDocument();
        expect(screen.getByRole('option', { name: /Engineering/i })).toBeInTheDocument();
      });
    });

    it('excludes org-admin groups from the dropdown but keeps normal and read-only-admin groups (RD-1099)', async () => {
      const user = userEvent.setup();
      const orgAdminGroup = {
        ...mockGroup,
        id: 'group-admin',
        name: 'Org Admins',
        path: 'admins',
        is_org_admin: true,
      };
      const readonlyAdminGroup = {
        ...mockGroup,
        id: 'group-ro-admin',
        name: 'Read Only Admins',
        path: 'ro-admins',
        is_org_readonly_admin: true,
      };
      renderForm({ groups: [mockGroup, orgAdminGroup, readonlyAdminGroup] });

      await user.click(screen.getByRole('combobox'));

      await waitFor(() => {
        expect(screen.getByRole('option', { name: /Root Group/i })).toBeInTheDocument();
      });
      // Read-only-admin assignment is delegation, not escalation — stays visible.
      expect(screen.getByRole('option', { name: /Read Only Admins/i })).toBeInTheDocument();
      // Full org-admin assignment is super-admin-only — hidden from the tier-2 dropdown.
      expect(screen.queryByRole('option', { name: /Org Admins/i })).not.toBeInTheDocument();
    });

    it('fetches groups when not supplied via props', async () => {
      let called = false;
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups', () => {
          called = true;
          return HttpResponse.json({
            data: [{ group: mockGroup, access: null }],
            total: 1,
            limit: 50,
            offset: 0,
          });
        })
      );

      renderForm({ groups: undefined });

      await waitFor(() => {
        expect(called).toBe(true);
      });
    });
  });

  describe('Local DID validation', () => {
    it('disables submit when DID is empty', () => {
      renderForm();
      expect(screen.getByRole('button', { name: /Onboard user/i })).toBeDisabled();
    });

    it('disables submit for too-short DID', async () => {
      const user = userEvent.setup();
      renderForm();

      await user.type(screen.getByLabelText(/User DID/i), 'did:short');
      // Even after picking a group, the button stays disabled until the
      // DID looks valid.
      await selectGroup(user, /Root Group/i);

      expect(screen.getByRole('button', { name: /Onboard user/i })).toBeDisabled();
    });

    it('disables submit for non-did: prefix', async () => {
      const user = userEvent.setup();
      renderForm();

      await user.type(
        screen.getByLabelText(/User DID/i),
        'not-a-did:iden3:privado:main:xxxxxxxxxxxxxxxxxxxx'
      );
      await selectGroup(user, /Root Group/i);

      expect(screen.getByRole('button', { name: /Onboard user/i })).toBeDisabled();
    });

    it('enables submit once a valid DID and a group are selected', async () => {
      const user = userEvent.setup();
      renderForm();

      await user.type(screen.getByLabelText(/User DID/i), VALID_DID);
      await selectGroup(user, /Root Group/i);

      await waitFor(() => {
        expect(screen.getByRole('button', { name: /Onboard user/i })).not.toBeDisabled();
      });
    });
  });

  describe('Submission', () => {
    it('POSTs DID + group_id to /orgs/:orgId/memberships/by-did and calls onSave', async () => {
      const user = userEvent.setup();
      const onSave = vi.fn();
      let captured: { did: string; group_id: string } | null = null;

      server.use(
        http.post(
          '/api/v1/admin/orgs/:orgId/memberships/by-did',
          async ({ request, params }) => {
            expect(params.orgId).toBe('org-1');
            captured = (await request.json()) as { did: string; group_id: string };
            return HttpResponse.json({
              membership: {
                id: 'membership-new',
                user_id: 'user-onboarded',
                group_id: captured.group_id,
                source: 'admin',
                zk_credential_ref: '',
                expires_at: null,
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString(),
              },
              user_id: 'user-onboarded',
            });
          }
        )
      );

      renderForm({ onSave });

      await user.type(screen.getByLabelText(/User DID/i), VALID_DID);
      await selectGroup(user, /Root Group/i);
      await user.click(screen.getByRole('button', { name: /Onboard user/i }));

      await waitFor(() => {
        expect(captured).not.toBeNull();
        expect(captured?.did).toBe(VALID_DID);
        expect(captured?.group_id).toBe('group-1');
        expect(onSave).toHaveBeenCalledTimes(1);
        expect(onSave).toHaveBeenCalledWith({
          userId: 'user-onboarded',
          membership: expect.objectContaining({
            id: 'membership-new',
            user_id: 'user-onboarded',
            group_id: 'group-1',
          }),
        });
      });
    });

    it('trims leading/trailing whitespace from the DID', async () => {
      const user = userEvent.setup();
      let captured: { did: string; group_id: string } | null = null;

      server.use(
        http.post(
          '/api/v1/admin/orgs/:orgId/memberships/by-did',
          async ({ request }) => {
            captured = (await request.json()) as { did: string; group_id: string };
            return HttpResponse.json({
              membership: {
                id: 'membership-new',
                user_id: 'user-onboarded',
                group_id: 'group-1',
                source: 'admin',
                zk_credential_ref: '',
                expires_at: null,
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString(),
              },
              user_id: 'user-onboarded',
            });
          }
        )
      );

      renderForm();

      await user.type(screen.getByLabelText(/User DID/i), `  ${VALID_DID}  `);
      await selectGroup(user, /Root Group/i);
      await user.click(screen.getByRole('button', { name: /Onboard user/i }));

      await waitFor(() => {
        expect(captured?.did).toBe(VALID_DID);
      });
    });
  });

  describe('Error handling', () => {
    it('surfaces a friendly "already in group" message on 409', async () => {
      const user = userEvent.setup();

      server.use(
        http.post('/api/v1/admin/orgs/:orgId/memberships/by-did', () => {
          return HttpResponse.json(
            { error: 'user is already a member of this group' },
            { status: 409 }
          );
        })
      );

      renderForm();

      await user.type(screen.getByLabelText(/User DID/i), VALID_DID);
      await selectGroup(user, /Root Group/i);
      await user.click(screen.getByRole('button', { name: /Onboard user/i }));

      await waitFor(() => {
        expect(
          screen.getByText('User is already a member of this group')
        ).toBeInTheDocument();
      });
    });

    it('surfaces an "access denied" message on 403 (caller not full-admin)', async () => {
      const user = userEvent.setup();

      server.use(
        http.post('/api/v1/admin/orgs/:orgId/memberships/by-did', () => {
          return HttpResponse.json({ error: 'access denied' }, { status: 403 });
        })
      );

      renderForm();

      await user.type(screen.getByLabelText(/User DID/i), VALID_DID);
      await selectGroup(user, /Root Group/i);
      await user.click(screen.getByRole('button', { name: /Onboard user/i }));

      await waitFor(() => {
        expect(screen.getByText(/Access denied/i)).toBeInTheDocument();
      });
    });

    it('surfaces an "access denied" message on 403 (group in foreign org)', async () => {
      // Backend deliberately returns identical opaque strings for both
      // 403 paths; the UI must treat them the same.
      const user = userEvent.setup();

      server.use(
        http.post('/api/v1/admin/orgs/:orgId/memberships/by-did', () => {
          return HttpResponse.json(
            { error: 'access denied to target group' },
            { status: 403 }
          );
        })
      );

      renderForm();

      await user.type(screen.getByLabelText(/User DID/i), VALID_DID);
      await selectGroup(user, /Root Group/i);
      await user.click(screen.getByRole('button', { name: /Onboard user/i }));

      await waitFor(() => {
        expect(screen.getByText(/Access denied/i)).toBeInTheDocument();
      });
    });

    it('surfaces the backend error string on 400', async () => {
      const user = userEvent.setup();

      server.use(
        http.post('/api/v1/admin/orgs/:orgId/memberships/by-did', () => {
          return HttpResponse.json(
            { error: 'invalid request body' },
            { status: 400 }
          );
        })
      );

      renderForm();

      await user.type(screen.getByLabelText(/User DID/i), VALID_DID);
      await selectGroup(user, /Root Group/i);
      await user.click(screen.getByRole('button', { name: /Onboard user/i }));

      await waitFor(() => {
        expect(screen.getByText('invalid request body')).toBeInTheDocument();
      });
    });

    it('shows a generic error when the network call fails', async () => {
      const user = userEvent.setup();

      server.use(
        http.post('/api/v1/admin/orgs/:orgId/memberships/by-did', () => {
          return HttpResponse.error();
        })
      );

      renderForm();

      await user.type(screen.getByLabelText(/User DID/i), VALID_DID);
      await selectGroup(user, /Root Group/i);
      await user.click(screen.getByRole('button', { name: /Onboard user/i }));

      await waitFor(() => {
        expect(
          screen.getByText('Failed to onboard user. Please try again.')
        ).toBeInTheDocument();
      });
    });
  });

  // RD-1239: org-admin groups are filtered out of the dropdown (RD-1099), so an
  // org whose only group is org-admin rendered "No groups in this organization"
  // — flatly untrue, and the submit button is then permanently disabled with no
  // explanation. A dead end with no way to read it.
  describe('Empty group list explains itself (RD-1239)', () => {
    const orgAdminGroup = {
      ...mockGroup,
      id: 'group-admin',
      name: 'Org Admins',
      path: 'admins',
      is_org_admin: true,
    };

    it('says the org has no groups at all when it genuinely has none', () => {
      renderForm({ groups: [] });

      expect(screen.getByTestId('onboard-no-groups')).toBeInTheDocument();
      expect(screen.getByText(/no groups yet/i)).toBeInTheDocument();
      expect(screen.getByText(/Groups tab/i)).toBeInTheDocument();
    });

    it('explains that org-admin-only groups are not assignable here', () => {
      renderForm({ groups: [orgAdminGroup] });

      expect(screen.getByTestId('onboard-no-assignable-groups')).toBeInTheDocument();
      // Must not claim the org has no groups — it has one, just not one this
      // caller may assign.
      expect(screen.queryByText(/no groups yet/i)).not.toBeInTheDocument();
      expect(screen.getByText(/org-admin/i)).toBeInTheDocument();
      expect(screen.getByText(/Groups tab/i)).toBeInTheDocument();
    });

    it('says the fetch failed rather than advising a group be created', async () => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups', () => HttpResponse.error())
      );

      renderForm({ groups: undefined });

      expect(await screen.findByTestId('onboard-groups-error')).toBeInTheDocument();
      // "Create one in the Groups tab" is wrong advice for a network failure.
      expect(screen.queryByTestId('onboard-no-groups')).not.toBeInTheDocument();
    });

    it('keeps the submit button disabled in both empty states', () => {
      const { unmount } = renderForm({ groups: [] });
      expect(screen.getByRole('button', { name: /Onboard user/i })).toBeDisabled();
      unmount();

      renderForm({ groups: [orgAdminGroup] });
      expect(screen.getByRole('button', { name: /Onboard user/i })).toBeDisabled();
    });
  });

  describe('Cancel', () => {
    it('calls onClose when cancel is clicked', async () => {
      const user = userEvent.setup();
      const onClose = vi.fn();

      renderForm({ onClose });

      await user.click(screen.getByRole('button', { name: /Cancel/i }));

      expect(onClose).toHaveBeenCalledTimes(1);
    });
  });
});
