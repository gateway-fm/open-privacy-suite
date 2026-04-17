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
        title: "Privacy Requirements",
        href: "/docs/security/privacy-requirements",
      },
      { title: "Compliance", href: "/docs/compliance" },
      { title: "Selective Disclosure", href: "/docs/disclosure" },
      { title: "Block Explorer", href: "/docs/explorer" },
    ],
  },
  {
    title: "API Reference",
    items: [{ title: "API Reference", href: "/docs/api" }],
  },
  {
    title: "Operations",
    items: [
      { title: "Contract Deployment", href: "/docs/deployment" },
      { title: "Scaling", href: "/docs/scaling" },
      { title: "Testing", href: "/docs/testing" },
      { title: "Troubleshooting", href: "/docs/troubleshooting" },
    ],
  },
];

export const flatNavItems: NavItem[] = navigation.flatMap(
  (group) => group.items
);
