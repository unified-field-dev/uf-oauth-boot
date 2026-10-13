use crate::privacy_policies::LEPTON_DELIVERY_GATE;
use valence::prelude::*;
use valence::privacy_policies::common::{BLOCK_ALL, SYSTEM_ONLY};

valence_schema! {
    LeptonDeliverySettings {
        repository: "https://github.com/unified-field-dev/uf-oauth-boot",
        table: "lepton_delivery_settings",
        version: "0.1.0",
        database: lepton_host_adapter::embedded_surreal::IDENTITY_DEFAULT_STORAGE,
        description: "Singleton (id `delivery`): non-secret email, SMS, OAuth and TOTP-key settings for Lepton sign-in. Secret values live in Neutrino, never here.",

        policies: {
            read: {
                always_allow: [SUPER_USER_GROUP_MEMBER],
                allow: [LEPTON_DELIVERY_GATE, SYSTEM_ONLY],
            },
            create: {
                always_allow: [SUPER_USER_GROUP_MEMBER],
                allow: [LEPTON_DELIVERY_GATE, SYSTEM_ONLY],
            },
            update: {
                always_allow: [SUPER_USER_GROUP_MEMBER],
                allow: [LEPTON_DELIVERY_GATE, SYSTEM_ONLY],
            },
            delete: {
                always_block: [BLOCK_ALL],
            },
        },

        fields: [
            id: {
                r#type: FieldType::String,
                primary_key: true,
                required: true,
            },
            revision: {
                r#type: FieldType::Integer,
                required: true,
            },
            settings: {
                r#type: FieldType::Json,
                required: true,
            },
            updated_at: {
                r#type: FieldType::DateTime,
                required: true,
            }
        ],
    }
}
