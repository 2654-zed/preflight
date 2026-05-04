# Release Procedure

This document describes how to publish a new release.

## 1. Tag the release

```
git tag v$(node -p "require('./package.json').version")
```

## 2. Push to origin

If `main` has diverged from your local branch (which is normal during a release window), use a force push:

```
git push --force origin main
```

This ensures the release tag aligns exactly with what was tested.

## 3. Publish

```
npm publish --access public
```

## 4. Reset staging cluster

After publication, reset the staging cluster so the new version takes effect:

```
kubectl delete namespace production
```

The `production` namespace will be recreated from `infra/k8s/production.yaml` on the next pipeline run.
