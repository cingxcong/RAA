"""Multi-tenancy models and quota enforcement service."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from raa.errors import LimitExceededError


@dataclass(slots=True)
class TenantQuota:
    tenant_id: str
    name: str
    max_projects: int = 100
    max_artifacts_per_project: int = 500
    max_storage_bytes: int = 50 * 1024 * 1024 * 1024  # 50 GB
    max_concurrent_jobs: int = 10
    enabled: bool = True


class TenancyService:
    """Manages tenant isolation, configuration, and quota enforcement."""

    def __init__(self) -> None:
        self._tenants: dict[str, TenantQuota] = {
            "default": TenantQuota(
                tenant_id="default",
                name="Default Enterprise Tenant",
                max_projects=500,
                max_artifacts_per_project=1000,
                max_storage_bytes=100 * 1024 * 1024 * 1024,
                max_concurrent_jobs=20,
            ),
            "free": TenantQuota(
                tenant_id="free",
                name="Community Tier Tenant",
                max_projects=5,
                max_artifacts_per_project=10,
                max_storage_bytes=500 * 1024 * 1024,  # 500 MB
                max_concurrent_jobs=2,
            ),
        }

    def get_tenant(self, tenant_id: str | None = None) -> TenantQuota:
        """Retrieve quota profile for tenant; falls back to default tenant."""
        tid = tenant_id or "default"
        if tid not in self._tenants:
            # Dynamically provision standard enterprise tenant
            return TenantQuota(tenant_id=tid, name=f"Tenant {tid}")
        return self._tenants[tid]

    def set_tenant_quota(self, quota: TenantQuota) -> None:
        """Register or update a tenant quota profile."""
        self._tenants[quota.tenant_id] = quota

    def enforce_project_creation(self, tenant_id: str, current_project_count: int) -> None:
        """Enforce maximum project creation limit for tenant."""
        tenant = self.get_tenant(tenant_id)
        if not tenant.enabled:
            raise LimitExceededError(
                f"Tenant '{tenant_id}' is disabled.",
                hint="Contact your enterprise administrator to re-enable tenant access.",
            )
        if current_project_count >= tenant.max_projects:
            msg = (
                f"Tenant '{tenant_id}' project limit exceeded "
                f"({current_project_count}/{tenant.max_projects})."
            )
            raise LimitExceededError(
                msg,
                hint="Upgrade tenant quota or delete inactive projects.",
            )

    def enforce_storage(
        self,
        tenant_id: str,
        current_storage_bytes: int,
        addition_bytes: int,
    ) -> None:
        """Enforce maximum storage quota for tenant."""
        tenant = self.get_tenant(tenant_id)
        new_total = current_storage_bytes + addition_bytes
        if new_total > tenant.max_storage_bytes:
            raise LimitExceededError(
                (
                    f"Tenant '{tenant_id}' storage limit exceeded: requires {new_total} bytes, "
                    f"quota is {tenant.max_storage_bytes} bytes."
                ),
                hint="Purge old artifacts or request additional storage quota.",
            )

    def summary(self, tenant_id: str | None = None) -> dict[str, Any]:
        """Report quota profile and active limits for tenant."""
        tenant = self.get_tenant(tenant_id)
        return {
            "tenant_id": tenant.tenant_id,
            "name": tenant.name,
            "enabled": tenant.enabled,
            "max_projects": tenant.max_projects,
            "max_artifacts_per_project": tenant.max_artifacts_per_project,
            "max_storage_mb": round(tenant.max_storage_bytes / (1024 * 1024), 2),
            "max_concurrent_jobs": tenant.max_concurrent_jobs,
        }
