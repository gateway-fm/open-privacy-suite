import Link from "next/link";
import {
  Shield,
  Lock,
  Eye,
  KeyRound,
  ArrowRight,
  Github,
  Database,
  Network,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
} from "@/components/ui/card";

export default function HomePage() {
  return (
    <div className="flex flex-col">
      {/* Hero */}
      <section className="relative overflow-hidden border-b">
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top,rgba(137,80,250,0.08),transparent_70%)]" />
        <div className="relative mx-auto max-w-7xl px-4 md:px-6 py-24 md:py-32">
          <div className="max-w-3xl">
            <h1 className="text-4xl md:text-6xl font-bold tracking-tight mb-6">
              <span className="text-primary">Open Privacy Suite</span>
            </h1>
            <p className="text-xl md:text-2xl text-muted-foreground mb-4">
              Privacy-preserving JSON-RPC proxy for Ethereum nodes.
            </p>
            <p className="text-base text-muted-foreground mb-8 max-w-2xl">
              Zero-knowledge proof authentication with Privado ID, hierarchical
              RBAC with method-level and contract-level permissions, and runtime
              transaction tracing for comprehensive cross-org isolation.
            </p>
            <div className="flex flex-wrap gap-3">
              <Button size="lg" asChild>
                <Link href="/docs/getting-started">
                  Get Started
                  <ArrowRight className="size-4" />
                </Link>
              </Button>
              <Button size="lg" variant="outline" asChild>
                <a
                  href="https://github.com/LFDT-Permissioned-Privacy-Control/permissioned-privacy-control"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  <Github className="size-4" />
                  GitHub
                </a>
              </Button>
            </div>
          </div>
        </div>
      </section>

      {/* Feature Cards */}
      <section className="mx-auto max-w-7xl px-4 md:px-6 py-16 md:py-24">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <Card className="bg-card hover:shadow-md transition-shadow">
            <CardHeader>
              <div className="size-10 rounded-lg bg-primary/10 flex items-center justify-center mb-2">
                <KeyRound className="size-5 text-primary" />
              </div>
              <CardTitle className="text-lg">ZK-Proof Auth</CardTitle>
              <CardDescription>
                Privado ID zero-knowledge proofs with ProofOfHumanity. Users
                prove identity without revealing private keys or personal data.
              </CardDescription>
            </CardHeader>
          </Card>

          <Card className="bg-card hover:shadow-md transition-shadow">
            <CardHeader>
              <div className="size-10 rounded-lg bg-primary/10 flex items-center justify-center mb-2">
                <Shield className="size-5 text-primary" />
              </div>
              <CardTitle className="text-lg">Hierarchical RBAC</CardTitle>
              <CardDescription>
                Multi-tenant, group-centric permissions with method-level,
                contract-level, and function selector restrictions. Admin,
                deploy and upgrade claims.
              </CardDescription>
            </CardHeader>
          </Card>

          <Card className="bg-card hover:shadow-md transition-shadow">
            <CardHeader>
              <div className="size-10 rounded-lg bg-primary/10 flex items-center justify-center mb-2">
                <Eye className="size-5 text-primary" />
              </div>
              <CardTitle className="text-lg">Runtime Tracing</CardTitle>
              <CardDescription>
                Every transaction traced via debug_traceCall for comprehensive
                cross-org isolation. Prevents unauthorized contract access at
                the EVM level.
              </CardDescription>
            </CardHeader>
          </Card>
        </div>
      </section>

      {/* Architecture Diagram */}
      <section className="border-y bg-muted/30">
        <div className="mx-auto max-w-7xl px-4 md:px-6 py-16 md:py-24">
          <h2 className="text-2xl md:text-3xl font-bold mb-8 text-center">
            Architecture
          </h2>
          <div className="max-w-3xl mx-auto">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {/* Row 1: Client */}
              <div className="md:col-span-3 rounded-lg border bg-card p-4 text-center">
                <div className="flex items-center justify-center gap-2 mb-1">
                  <Network className="size-4 text-primary" />
                  <span className="font-semibold">Client (Wallet)</span>
                </div>
                <p className="text-xs text-muted-foreground">
                  MetaMask, ethers.js, or any JSON-RPC client
                </p>
              </div>

              {/* Arrow */}
              <div className="md:col-span-3 flex justify-center text-muted-foreground">
                <svg
                  width="24"
                  height="32"
                  viewBox="0 0 24 32"
                  fill="none"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <path
                    d="M12 0v24m0 0l-6-6m6 6l6-6"
                    stroke="currentColor"
                    strokeWidth="2"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                </svg>
              </div>

              {/* Row 2: Open Privacy Suite */}
              <div className="md:col-span-3 rounded-lg border-2 border-primary/30 bg-card p-4 text-center">
                <div className="flex items-center justify-center gap-2 mb-1">
                  <Lock className="size-4 text-primary" />
                  <span className="font-semibold">Open Privacy Suite</span>
                </div>
                <p className="text-xs text-muted-foreground">
                  Auth &rarr; RBAC &rarr; Trace &rarr; Proxy
                </p>
                <div className="mt-2 flex justify-center gap-3 text-xs">
                  <span className="rounded bg-secondary px-2 py-0.5">
                    ZK Verification
                  </span>
                  <span className="rounded bg-secondary px-2 py-0.5">
                    Access Control
                  </span>
                  <span className="rounded bg-secondary px-2 py-0.5">
                    Runtime Tracing
                  </span>
                </div>
              </div>

              {/* Arrow */}
              <div className="md:col-span-3 flex justify-center text-muted-foreground">
                <svg
                  width="24"
                  height="32"
                  viewBox="0 0 24 32"
                  fill="none"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <path
                    d="M12 0v24m0 0l-6-6m6 6l6-6"
                    stroke="currentColor"
                    strokeWidth="2"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                </svg>
              </div>

              {/* Row 3: Ethereum Node + PostgreSQL side by side */}
              <div className="md:col-span-2 rounded-lg border bg-card p-4 text-center">
                <div className="flex items-center justify-center gap-2 mb-1">
                  <Network className="size-4 text-primary" />
                  <span className="font-semibold">Ethereum Node</span>
                </div>
                <p className="text-xs text-muted-foreground">
                  JSON-RPC execution layer
                </p>
              </div>

              <div className="rounded-lg border bg-card p-4 text-center">
                <div className="flex items-center justify-center gap-2 mb-1">
                  <Database className="size-4 text-primary" />
                  <span className="font-semibold">PostgreSQL</span>
                </div>
                <p className="text-xs text-muted-foreground">
                  Orgs, users, permissions
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Quick Start */}
      <section className="mx-auto max-w-7xl px-4 md:px-6 py-16 md:py-24">
        <h2 className="text-2xl md:text-3xl font-bold mb-8 text-center">
          Quick Start
        </h2>
        <div className="max-w-2xl mx-auto">
          <div className="rounded-lg border bg-[#0d1117] p-6 font-mono text-sm text-[#e6edf3]">
            <div className="text-[#8b949e] mb-2"># Start the stack</div>
            <div>
              <span className="text-[#79c0ff]">docker-compose</span> up -d
            </div>
            <div className="mt-4 text-[#8b949e]"># Open admin UI</div>
            <div>
              <span className="text-[#79c0ff]">open</span>{" "}
              http://localhost:5173
            </div>
          </div>
          <div className="mt-6 text-center">
            <Button asChild>
              <Link href="/docs/getting-started">
                Read the full guide
                <ArrowRight className="size-4" />
              </Link>
            </Button>
          </div>
        </div>
      </section>

      {/* Component Cards */}
      <section className="border-t bg-muted/30">
        <div className="mx-auto max-w-7xl px-4 md:px-6 py-16 md:py-24">
          <h2 className="text-2xl md:text-3xl font-bold mb-8 text-center">
            Documentation
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <Link href="/docs/authentication" className="group">
              <Card className="h-full bg-card group-hover:shadow-md transition-shadow">
                <CardHeader>
                  <CardTitle className="text-lg flex items-center gap-2">
                    <KeyRound className="size-4 text-primary" />
                    Authentication
                  </CardTitle>
                  <CardDescription>
                    ZK-proof authentication with Privado ID, Azure AD SSO
                    integration, and admin bootstrap flow.
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <span className="text-sm text-primary group-hover:underline">
                    View docs &rarr;
                  </span>
                </CardContent>
              </Card>
            </Link>

            <Link href="/docs/rbac" className="group">
              <Card className="h-full bg-card group-hover:shadow-md transition-shadow">
                <CardHeader>
                  <CardTitle className="text-lg flex items-center gap-2">
                    <Shield className="size-4 text-primary" />
                    RBAC
                  </CardTitle>
                  <CardDescription>
                    Hierarchical role-based access control with org, group, and
                    user-level permissions. Method, contract, and selector
                    restrictions.
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <span className="text-sm text-primary group-hover:underline">
                    View docs &rarr;
                  </span>
                </CardContent>
              </Card>
            </Link>

            <Link href="/docs/security" className="group">
              <Card className="h-full bg-card group-hover:shadow-md transition-shadow">
                <CardHeader>
                  <CardTitle className="text-lg flex items-center gap-2">
                    <Lock className="size-4 text-primary" />
                    Security
                  </CardTitle>
                  <CardDescription>
                    Runtime transaction tracing, cross-org isolation, contract
                    deployment pre-registration, and fail-closed access model.
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <span className="text-sm text-primary group-hover:underline">
                    View docs &rarr;
                  </span>
                </CardContent>
              </Card>
            </Link>
          </div>
        </div>
      </section>
    </div>
  );
}
