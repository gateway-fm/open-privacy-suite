# Contributing

Thank you for contributing to Open Privacy Suite.

## License

By contributing, you agree that your contribution is licensed under the Apache
License, Version 2.0.

## Developer Certificate of Origin

This project uses the Developer Certificate of Origin 1.1. Sign off each commit
with:

```bash
git commit -s
```

The sign-off certifies that you have the right to submit the contribution under
the project license.

CI enforces this on every pull request (the `DCO` check). Merge commits and bot
commits are exempt. If a commit is missing the sign-off:

```bash
git rebase --signoff origin/main
git push --force-with-lease
```

(Force-push works on fork branches. Branches inside this repository are
force-push-protected — re-create the branch and open a fresh PR instead.)

## Development

Before opening a pull request:

- Keep changes focused and reviewable.
- Add or update tests when changing behavior.
- Do not commit secrets, private audit reports, local agent state, or generated
  credentials.
- Do not report security issues in public pull requests or issues; follow
  SECURITY.md.

Useful checks:

```bash
go test ./...
npm --prefix frontend test
npm --prefix frontend run lint
npm --prefix site run lint
```

Some checks require optional services such as Postgres, Redis, Anvil, or sibling
Gateway repositories. Public-fork-safe CI coverage is part of the open-source
readiness TODO.

### Optional staging authentication tools

The application build and CI test workflows do not require `wallet-emulator-js`.
The `staging-create-test-accs`, `staging-auth-users`, and `staging-test-accs`
Make targets use it to create test identities and authenticate them against a
staging proxy. It is an external tool, not a submodule or part of this source
distribution.

If you have access to [the wallet-emulator repository](https://github.com/gateway-fm/wallet-emulator-js),
obtain a separate checkout and follow its own dependency-installation
instructions. The previously pinned revision was
`c46f7f75e924ca72d30a200c13de898c2ba1eb68`. Configure its absolute path:

```bash
export WALLET_EMULATOR_DIR="/absolute/path/to/wallet-emulator-js"
make staging-test-accs PROXY_URL=https://your-staging-proxy.example.com
```

The helper creates identities in that checkout and fetches its auth-v2 circuit
artifacts into `PRIVADO_CIRCUITS_DIR` (default: `~/.privado-circuits`). To obtain
a JWT for one test identity:

```bash
PROXY_URL=https://your-staging-proxy.example.com \
  "$WALLET_EMULATOR_DIR/scripts/auth-as.sh" alice
```

`make staging-cleanup` removes both the configured circuit directory's
`authV2` artifacts and the external checkout's `identities` directory. Run it
only when you intend to reset those test identities. Without access to the
external tool, use the development mock-auth flow described in the README.

## Repository transition and publishing

The LFDT destination is
[`LFDT-Permissioned-Privacy-Control/permissioned-privacy-control`](https://github.com/LFDT-Permissioned-Privacy-Control/permissioned-privacy-control).
Preparation changes are reviewed and merged in the existing repository first.
The initial LFDT commit must have the same Git tree as the selected merged
source commit, including submodule pins, and carry a DCO sign-off. Record that
source commit in the import commit message. Do not apply extra file edits only
to the import. Subsequent development uses pull requests in the LFDT repository.

The documentation links in this preparation change point to LFDT. Coordinate
the merge with the initial import and docs deployment so those links become
available at cutover. GitHub Pages builds derive their path from
`GITHUB_REPOSITORY`; local production builds default to
`/permissioned-privacy-control`. `DOCS_BASE_PATH` can override either, including
an empty value for a custom domain.

For the LFDT docs deployment, enable GitHub Pages with GitHub Actions as its
source, configure the `github-pages` environment, and set the repository
variable `DOCS_PAGES_ENABLED=true`. The existing Gateway docs deployment keeps
working without that variable.

The release and dev-image workflows retain Gateway's Docker Hub destinations
and are restricted to the Gateway repository. The LFDT import therefore does
not publish images to those accounts. Configure LFDT artifact publication in
a separate reviewed change when its registry and credentials are agreed. Dry-run
image builds and the normal CI checks remain available in the new repository.
