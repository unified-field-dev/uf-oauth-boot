//! Valence privacy evaluator for the delivery settings row.

use std::any::Any;

use async_trait::async_trait;
use valence::{Actor, ActorContext, Error, PolicyEvaluator, PrivacyOperation, Result, Valence};

/// Gauge permission that gates every read and write of delivery settings.
pub const MANAGE_DELIVERY_PERMISSION: &str = "LeptonManageDelivery";

/// Policy rule for [`MANAGE_DELIVERY_PERMISSION`].
pub const LEPTON_DELIVERY_GATE: LeptonDeliveryGate = LeptonDeliveryGate;

/// Allows System and actors holding [`MANAGE_DELIVERY_PERMISSION`].
///
/// Uses raw Gauge walks, which are safe inside a policy evaluator. The typed
/// `actor_can` re-enters ORM privacy and would recurse.
#[derive(Debug, Clone, Copy)]
pub struct LeptonDeliveryGate;

#[async_trait]
impl PolicyEvaluator for LeptonDeliveryGate {
    fn name(&self) -> &'static str {
        "lepton::LEPTON_MANAGE_DELIVERY"
    }

    fn description(&self) -> Option<&'static str> {
        Some("LeptonManageDelivery Gauge permission (raw walks)")
    }

    async fn evaluate(
        &self,
        _op: PrivacyOperation,
        _record: &serde_json::Value,
        actor: &dyn ActorContext,
        v: &Valence,
    ) -> Result<bool> {
        let viewer: Actor = serde_json::from_value(actor.actor_json().clone())
            .map_err(|e| Error::Internal(format!("invalid actor context: {e}")))?;
        if viewer.is_system() {
            return Ok(true);
        }
        gauge::actor_can_raw::actor_can_raw(v, MANAGE_DELIVERY_PERMISSION)
            .await
            .map_err(|e| Error::Privacy(format!("LeptonManageDelivery raw check failed: {e}")))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
