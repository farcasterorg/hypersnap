use crate::core::validations::error::ValidationError;
use crate::proto;

/// Validate the structural correctness of a `HyperMessage`.
///
/// This performs hash verification and field-level checks but does NOT
/// verify the EIP-712 custody signature — that requires a custody address
/// lookup and is done in the engine layer.
pub fn validate_hyper_message(message: &proto::HyperMessage) -> Result<(), ValidationError> {
    // 1. Data must be present
    let data = message.data.as_ref().ok_or(ValidationError::MissingData)?;

    // 2. Hash verification: blake3 of data_bytes (or encoded data)
    let data_bytes = message
        .data_bytes
        .as_ref()
        .map(|b| b.clone())
        .unwrap_or_else(|| {
            use prost::Message;
            data.encode_to_vec()
        });
    let computed_hash = crate::core::util::calculate_message_hash(&data_bytes);
    if computed_hash != message.hash {
        return Err(ValidationError::InvalidHash);
    }

    // 3. Hash scheme must be blake3
    if message.hash_scheme != proto::HashScheme::Blake3 as i32 {
        return Err(ValidationError::InvalidHashScheme);
    }

    // 4. For signer messages: signer must be 20-byte ETH address
    let msg_type = proto::HyperMessageType::try_from(data.r#type)
        .map_err(|_| ValidationError::InvalidMessageType)?;

    match msg_type {
        proto::HyperMessageType::SignerAdd => {
            validate_signer_envelope(message)?;
            validate_signer_add_body(data)?;
        }
        proto::HyperMessageType::SignerRemove => {
            validate_signer_envelope(message)?;
            validate_signer_remove_body(data)?;
        }
        _ => {
            return Err(ValidationError::InvalidMessageType);
        }
    }

    Ok(())
}

/// Common envelope checks for signer messages.
fn validate_signer_envelope(message: &proto::HyperMessage) -> Result<(), ValidationError> {
    // Signer (custody address) must be 20 bytes
    if message.signer.len() != 20 {
        return Err(ValidationError::MissingOrInvalidSigner);
    }
    // Signature scheme must be EIP-712
    if message.signature_scheme != proto::SignatureScheme::Eip712 as i32 {
        return Err(ValidationError::InvalidSignatureScheme);
    }
    // Signature must be 65 bytes (r + s + v)
    if message.signature.len() != 65 {
        return Err(ValidationError::InvalidSignature);
    }
    Ok(())
}

/// Validate the body fields for a SignerAdd.
fn validate_signer_add_body(data: &proto::HyperMessageData) -> Result<(), ValidationError> {
    let body = match &data.body {
        Some(proto::hyper_message_data::Body::SignerAddBody(b)) => b,
        _ => return Err(ValidationError::MissingData),
    };
    // Ed25519 key must be 32 bytes
    if body.key.len() != 32 {
        return Err(ValidationError::InvalidData);
    }
    // key_type must be 1 (Ed25519)
    if body.key_type != 1 {
        return Err(ValidationError::InvalidData);
    }
    // deadline must be > 0
    if body.deadline == 0 {
        return Err(ValidationError::InvalidData);
    }
    // nonce must be > 0
    if body.nonce == 0 {
        return Err(ValidationError::InvalidData);
    }
    Ok(())
}

/// Validate the body fields for a SignerRemove.
fn validate_signer_remove_body(data: &proto::HyperMessageData) -> Result<(), ValidationError> {
    let body = match &data.body {
        Some(proto::hyper_message_data::Body::SignerRemoveBody(b)) => b,
        _ => return Err(ValidationError::MissingData),
    };
    // key must be 32 bytes
    if body.key.len() != 32 {
        return Err(ValidationError::InvalidData);
    }
    // deadline must be > 0
    if body.deadline == 0 {
        return Err(ValidationError::InvalidData);
    }
    // nonce must be > 0
    if body.nonce == 0 {
        return Err(ValidationError::InvalidData);
    }
    Ok(())
}
