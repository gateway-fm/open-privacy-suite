import Link from "next/link";
import { Shield } from "lucide-react";

export function SiteFooter() {
  return (
    <footer className="border-t py-8">
      <div className="mx-auto max-w-7xl px-4 md:px-6">
        <div className="flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Shield className="size-4 text-primary" />
            <span>Open Privacy Suite by Gateway.fm</span>
          </div>
          <nav className="flex items-center gap-6 text-sm text-muted-foreground">
            <Link href="/docs/getting-started" className="hover:text-foreground transition-colors">
              Docs
            </Link>
            <a
              href="https://github.com/LFDT-Permissioned-Privacy-Control/permissioned-privacy-control"
              target="_blank"
              rel="noopener noreferrer"
              className="hover:text-foreground transition-colors"
            >
              GitHub
            </a>
            <a
              href="https://gateway.fm"
              target="_blank"
              rel="noopener noreferrer"
              className="hover:text-foreground transition-colors"
            >
              Gateway.fm
            </a>
          </nav>
        </div>
      </div>
    </footer>
  );
}
