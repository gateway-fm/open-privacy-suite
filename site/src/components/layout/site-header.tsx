"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Github, Menu, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { useState } from "react";
import { MobileNav } from "./mobile-nav";
import { VersionSelector } from "./version-selector";

export function SiteHeader() {
  const pathname = usePathname();
  const isDocsPage = pathname?.startsWith("/docs");
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <header className="sticky top-0 z-50 w-full border-b bg-card/80 backdrop-blur-sm">
      <div className="flex h-14 items-center px-4 md:px-6">
        <Link href="/" className="flex items-center gap-3 mr-6">
          <div className="font-mono text-xl font-bold flex items-center select-none">
            <span className="text-primary">&gt;</span>
            <span className="text-foreground">_</span>
          </div>
          <div className="hidden sm:block min-w-0">
            <h1 className="text-sm font-semibold font-mono truncate tracking-tight">
              Open Privacy Suite
            </h1>
            <p className="text-xs text-muted-foreground font-mono truncate">
              Documentation
            </p>
          </div>
        </Link>

        <nav className="hidden md:flex items-center gap-1">
          <Link
            href="/docs/getting-started"
            className={cn(
              "px-3 py-1.5 text-sm font-mono font-medium rounded-md transition-all duration-150",
              isDocsPage
                ? "bg-primary text-primary-foreground"
                : "text-muted-foreground hover:text-foreground hover:bg-accent"
            )}
          >
            Docs
          </Link>
        </nav>

        <div className="flex-1" />

        <div className="hidden md:flex items-center gap-2">
          <VersionSelector />
          <Button variant="ghost" size="icon" asChild>
            <a
              href="https://github.com/LFDT-Permissioned-Privacy-Control/permissioned-privacy-control"
              target="_blank"
              rel="noopener noreferrer"
            >
              <Github className="size-4" />
              <span className="sr-only">GitHub</span>
            </a>
          </Button>
        </div>

        <Button
          variant="ghost"
          size="icon"
          className="md:hidden"
          onClick={() => setMobileOpen(!mobileOpen)}
        >
          {mobileOpen ? <X className="size-5" /> : <Menu className="size-5" />}
        </Button>
      </div>

      {mobileOpen && <MobileNav onClose={() => setMobileOpen(false)} />}
    </header>
  );
}
