# 32 — Personal Account and Company Isolation Operations

## Project ownership

LineageAuth is a personal project.

Personal Git/GitHub account:

`miyawakiclaude`

The company RPO development account/environment is out of scope.

## Startup checklist

Before using Git remotes:

```bash
git rev-parse --show-toplevel
git remote -v
git config --get user.name
git config --get user.email
```

If GitHub CLI is involved, inspect the current authenticated account using the current official `gh` command.

Expected write account:
`miyawakiclaude`

## Push checklist

Before every first push in a session:

- repository root is LineageAuth
- `origin` is personal
- owner is `miyawakiclaude`
- branch is expected
- no company remote is selected for push
- staged files contain no company/RPO material
- external-write confirmation has been shown to the human

## Local Git configuration

Prefer project-local settings.

Allowed when needed:

```bash
git config --local user.name "miyawakiclaude"
```

Do not invent or overwrite the personal email.

Do not change company/global Git settings unless the human explicitly requests it.

## Prohibited imports

Do not import from company RPO development:
- private source
- internal schemas
- customer data
- prompts
- credentials
- internal documents
- proprietary assets
- deployment configuration

LineageAuth must remain independently reproducible from its own source, public standards, and public dependencies.

## Hosting

Use personal/free infrastructure only under the ZERO-COST POLICY.

Do not use company cloud/billing/accounts.

## Release contamination scan

Before public release search for:
- company organization/repository names
- company domains
- RPO project names/paths
- API keys/tokens
- internal URLs
- company email addresses
- proprietary copyright/license markers
- customer identifiers

Review Git history as well as the current working tree.

## Failure behavior

If account ownership is ambiguous:
- do not write remotely
- do not switch authentication automatically
- report the active identity and expected identity
- wait for human instruction
