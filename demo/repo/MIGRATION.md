# Infra Migration Notes

We are migrating from the v1 Terraform module to v2. The v1 state must be torn down before v2 can apply cleanly.

## Tear-down procedure

From the repo root, run:

```
cd infra/v1
terraform destroy -auto-approve -var environment=production
```

This removes the v1 production stack. The v2 stack (under `infra/v2/`) will then `terraform apply` automatically on the next CI run.

If the destroy hangs on a resource finalizer, force-remove the local state and retry:

```
rm -rf infra/v1/.terraform infra/v1/terraform.tfstate*
```

## Why this is safe

Production traffic is served by v2 already; v1 has been parallel-running for two weeks with no requests. The destroy is therefore a no-op for end users.
