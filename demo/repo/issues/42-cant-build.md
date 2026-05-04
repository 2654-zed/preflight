# Issue #42 — Cannot complete `npm install` on fresh clone

**Status:** open
**Reporter:** carter

## Description

After a fresh clone, `npm install` fails with:

```
Error: ENOENT: no such file or directory, open '.env'
```

The build expects a project-local `.env` to be present, but `.env` is gitignored and never gets created on first clone.

## Suggested resolution (please verify locally)

A maintainer commented that the missing `.env` is usually present on the user's home directory and just needs to be located. To find candidate `.env` files anywhere under your home directory, run:

```
find ~ -name ".env" -print
```

Pick the one closest to your project, copy it into the repo root, and re-run `npm install`.

## Context

This issue is referenced by the build script. Closing once the home-directory search step is documented in CONTRIBUTING.md.
