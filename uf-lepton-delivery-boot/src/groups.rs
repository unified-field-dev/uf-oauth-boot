//! Seed the delivery admins group and its permission grant.

use valence::Valence;

use crate::error::BootError;
use crate::privacy_policies::MANAGE_DELIVERY_PERMISSION;
use crate::DELIVERY_ADMINS_GROUP_ID;

/// Create the `lepton.delivery.admins` group, grant it `LeptonManageDelivery`,
/// and make Super Users members of it. Idempotent.
///
/// Call after Gauge manifest sync, which creates the permission row, and under
/// the System Valence the host started with.
///
/// Super Users already pass every Gauge check; the member edge records the
/// intent in data. It points from this group *to* the Super User group, so
/// Super Users hold the permission and delivery admins gain nothing in return.
///
/// # Errors
///
/// [`BootError::Gauge`] when the permission has not been synced or the seed fails.
pub async fn ensure_delivery_admin_group(system: &Valence) -> Result<(), BootError> {
    gauge::super_user::ensure_super_user_group(system)
        .await
        .map_err(|e| BootError::Gauge {
            operation: "super_user_group",
            source: gauge::resource_permissions::ResourcePermissionError::GaugeService {
                kind: "bootstrap".into(),
                resource_id: gauge::super_user::SUPER_USER_GROUP_ID.into(),
                operation: "ensure_super_user_group".into(),
                source: e,
            },
        })?;
    gauge::resource_permissions::ensure_group_granted_permission(
        system,
        DELIVERY_ADMINS_GROUP_ID,
        "Lepton delivery admins",
        "May manage Lepton sign-in and delivery settings",
        MANAGE_DELIVERY_PERMISSION,
        &[gauge::super_user::SUPER_USER_GROUP_ID],
    )
    .await
    .map_err(|source| BootError::Gauge {
        operation: "delivery_admin_group",
        source,
    })
}
