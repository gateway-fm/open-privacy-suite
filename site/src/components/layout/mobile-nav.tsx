"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { navigation } from "@/lib/navigation";
import { cn } from "@/lib/utils";
import { Github } from "lucide-react";
import { MobileVersionBadge } from "./version-selector";

interface MobileNavProps {
  onClose: () => void;
}

export function MobileNav({ onClose }: MobileNavProps) {
  const pathname = usePathname();

  return (
    <div className="md:hidden border-t bg-background px-4 pb-4 pt-2">
      <nav className="space-y-4">
        {navigation.map((group) => (
          <div key={group.title}>
            <h4 className="mb-1 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              {group.title}
            </h4>
            <ul className="space-y-1">
              {group.items.map((item) => {
                const isActive =
                  pathname === item.href || pathname === item.href + "/";
                return (
                  <li key={item.href}>
                    <Link
                      href={item.href}
                      onClick={onClose}
                      className={cn(
                        "block rounded-md px-3 py-2 text-sm transition-colors",
                        isActive
                          ? "bg-accent text-accent-foreground font-medium"
                          : "text-muted-foreground hover:text-foreground"
                      )}
                    >
                      {item.title}
                    </Link>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
        <div className="pt-2 border-t space-y-2">
          <MobileVersionBadge />
          <a
            href="https://github.com/LFDT-Permissioned-Privacy-Control/permissioned-privacy-control"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 px-3 py-2 text-sm text-muted-foreground hover:text-foreground"
            onClick={onClose}
          >
            <Github className="size-4" />
            GitHub
          </a>
        </div>
      </nav>
    </div>
  );
}
