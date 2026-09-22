import { Link } from 'react-router-dom';
import { ShieldCheck } from 'lucide-react';

interface ManagedStreamNoticeProps {
  /** What the screen lists, in the plural: "Groups", "Contracts", "Compliance settings". */
  subject: string;
  /** Where the document is edited. Platform-scope screens point at the platform document. */
  to?: string;
}

/**
 * ManagedStreamNotice replaces a screen's edit controls once a reviewed
 * configuration document owns the stream. The legacy write endpoints refuse
 * direct edits at that point, so the screen says so up front and sends the
 * administrator to the configuration screen instead of failing on click.
 */
export default function ManagedStreamNotice({ subject, to = '/admin/rbac/configuration' }: ManagedStreamNoticeProps) {
  return (
    <div
      role="status"
      data-testid="managed-stream-notice"
      className="flex items-start gap-2 p-3 rounded-lg bg-neutral-50 border border-neutral-200 text-neutral-700 text-sm"
    >
      <ShieldCheck className="w-4 h-4 shrink-0 mt-0.5" />
      <span>
        {subject} are managed by a reviewed configuration document. Direct edits are refused here; change the
        document on the{' '}
        <Link to={to} className="underline font-medium">
          Configuration
        </Link>{' '}
        tab and activate a revision.
      </span>
    </div>
  );
}
