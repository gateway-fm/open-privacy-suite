export interface NavItem {
  title: string;
  href: string;
}

export interface NavGroup {
  title: string;
  items: NavItem[];
}

export const navigation: NavGroup[] = [
  {
    title: "Getting Started",
    items: [
      { title: "Quick Start", href: "/docs/getting-started" },
      { title: "Architecture", href: "/docs/architecture" },
      { title: "Configuration", href: "/docs/configuration" },
    ],
  },
  {
    title: "Authentication",
    items: [
      { title: "Auth Flows", href: "/docs/authentication" },
      { title: "Azure AD / SSO", href: "/docs/azure-ad" },
    ],
  },
  {
    title: "Features",
    items: [
      { title: "RBAC", href: "/docs/rbac" },
      { title: "Security", href: "/docs/security" },
      {
        title: "Response Filtering",
        href: "/docs/security/response-filtering",
      },
      {
        title: "Method Access Policies",
        href: "/docs/security/method-policies",
      },
      {
        title: "Privacy Requirements",
        href: "/docs/security/privacy-requirements",
      },
      { title: "Compliance", href: "/docs/compliance" },
      { title: "Selective Disclosure", href: "/docs/disclosure" },
      { title: "Block Explorer", href: "/docs/explorer" },
      { title: "View as user", href: "/docs/security/view-as-user" },
    ],
  },
  {
    title: "API Reference",
    items: [
      { title: "API Overview", href: "/docs/api" },
      { title: "Interactive Reference", href: "/api-reference" },
    ],
  },
  {
    title: "Operations",
    items: [
      { title: "Operator Deployment", href: "/docs/operator-deployment" },
      { title: "User Onboarding", href: "/docs/operator-onboarding" },
      { title: "Contract Deployment", href: "/docs/deployment" },
      { title: "Audit Log Integrity", href: "/docs/security/audit-integrity" },
      { title: "Backup & Disaster Recovery", href: "/docs/backup-recovery" },
      { title: "Scaling", href: "/docs/scaling" },
      { title: "Testing", href: "/docs/testing" },
      { title: "Troubleshooting", href: "/docs/troubleshooting" },
    ],
  },
];

export const flatNavItems: NavItem[] = navigation.flatMap(
  (group) => group.items
);
