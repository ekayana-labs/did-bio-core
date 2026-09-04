//! The `did:bio` resolution algorithm (spec Section 6.2), decoupled from any
//! transport.
//!
//! The heart of this module is [`resolve_from_account`], a pure function
//! from a parsed DID plus an optional fetched account to a complete
//! [`DidResolution`]. Steps 1-5 of the algorithm (parse, cluster selection,
//! PDA derivation, account fetch) happen in the caller or in the
//! [`RegistryReader`] drivers; steps 6-9 (ownership and discriminator
//! checks, generative fallback, materialization, metadata) happen here.
//!
//! **Transport errors are not "not found".** Spec Section 6.2 permits the
//! generative fallback only for a genuinely absent account. A fetcher MUST
//! surface RPC failures as errors ([`RegistryReader::fetch_account`]
//! returning `Err`), never as `Ok(None)` - otherwise an unreachable or
//! malicious RPC node silently resurrects rotated out or deactivated keys
//! (the withholding attack, spec Section 7).

use crate::account::{vm_flags, DidAccountState, StoredVerificationMethod, PROGRAM_ID};
use crate::did::BioDid;
use crate::document::{
    default_context, DidDocument, DidDocumentMetadata, DidResolution, ServiceMap,
    VerificationMethodMap,
};
use crate::error::{resolution_error, Error};

/// A registry account as fetched from a Solana RPC node: its owner program
/// and raw data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawAccount {
    /// The program that owns the account.
    pub owner: [u8; 32],
    /// The account data, including the 8 byte discriminator.
    pub data: Vec<u8>,
}

/// Materialize one stored verification method as a document map
/// (spec Section 5.2).
pub fn verification_method_map(
    did: &BioDid,
    vm: &StoredVerificationMethod,
) -> Result<VerificationMethodMap, Error> {
    let id = did.url(&vm.fragment);
    let controller = did.to_string();
    match vm.method_type.key_codec() {
        Some(codec) => VerificationMethodMap::multikey(id, controller, codec, &vm.key_data),
        None => VerificationMethodMap::ml_dsa_87(id, controller, &vm.key_data),
    }
}

/// Materialize a DID document from registry state (spec Section 5).
///
/// The document's identifiers are derived from `did` - including its
/// network segment - so the same state materializes differently for
/// `did:bio:devnet:...` and `did:bio:...` (distinct DIDs by spec Section 4.2).
pub fn materialize_document(did: &BioDid, state: &DidAccountState) -> Result<DidDocument, Error> {
    let did_string = did.to_string();

    let mut controller: Vec<String> = state
        .native_controllers
        .iter()
        .map(|key| BioDid::new(did.network, *key).to_string())
        .collect();
    controller.extend(state.other_controllers.iter().cloned());

    let mut document = DidDocument {
        context: default_context(),
        id: did_string,
        controller,
        ..DidDocument::default()
    };

    for vm in &state.verification_methods {
        document
            .verification_method
            .push(verification_method_map(did, vm)?);
        let reference = did.url(&vm.fragment);
        for (flag, list) in [
            (vm_flags::AUTHENTICATION, &mut document.authentication),
            (vm_flags::ASSERTION, &mut document.assertion_method),
            (vm_flags::KEY_AGREEMENT, &mut document.key_agreement),
            (
                vm_flags::CAPABILITY_INVOCATION,
                &mut document.capability_invocation,
            ),
            (
                vm_flags::CAPABILITY_DELEGATION,
                &mut document.capability_delegation,
            ),
        ] {
            if vm.has_flag(flag) {
                list.push(reference.clone());
            }
        }
    }

    for service in &state.services {
        document.service.push(ServiceMap {
            id: did.url(&service.fragment),
            service_type: service.service_type.clone(),
            service_endpoint: service.endpoint.clone(),
        });
    }

    Ok(document)
}

/// The generative DID document for a DID with no registry entry
/// (spec Section 5.6): the subject key as a protected `#default` method carrying
/// all five verification relationships.
pub fn generative_document(did: &BioDid) -> DidDocument {
    materialize_document(did, &DidAccountState::generative(did.subject))
        .expect("generative state always materializes")
}

/// The minimal document of a deactivated DID (spec Section 5.7).
pub fn deactivated_document(did: &BioDid) -> DidDocument {
    DidDocument {
        context: default_context(),
        id: did.to_string(),
        ..DidDocument::default()
    }
}

/// Steps 6-9 of the resolution algorithm (spec Section 6.2): decide between the
/// generative fallback, the deactivated document, and full
/// materialization.
///
/// `account` is the result of fetching the DID's PDA
/// ([`crate::pda::find_did_account_address`]): `None` when no account
/// exists. An account that is empty or not owned by the registry program
/// resolves generatively (step 6). Undecodable account data yields an
/// `internalError` resolution, never a fallback.
pub fn resolve_from_account(did: &BioDid, account: Option<&RawAccount>) -> DidResolution {
    let account = match account {
        Some(account) if account.owner == PROGRAM_ID && !account.data.is_empty() => account,
        _ => {
            return DidResolution::success(
                generative_document(did),
                DidDocumentMetadata::generative(),
            )
        }
    };

    let state = match DidAccountState::from_account_data(&account.data) {
        Ok(state) => state,
        Err(_) => return DidResolution::error(resolution_error::INTERNAL_ERROR),
    };

    // Defensive: the account at the DID's PDA must be about this subject.
    // A mismatch means the caller fetched the wrong address.
    if state.subject != did.subject {
        return DidResolution::error(resolution_error::INTERNAL_ERROR);
    }

    if state.deactivated {
        return DidResolution::success(
            deactivated_document(did),
            DidDocumentMetadata::registered(true, state.version, state.updated_at),
        );
    }

    match materialize_document(did, &state) {
        Ok(document) => DidResolution::success(
            document,
            DidDocumentMetadata::registered(false, state.version, state.updated_at),
        ),
        Err(_) => DidResolution::error(resolution_error::INTERNAL_ERROR),
    }
}

/// Resolve a DID string against an already fetched account: step 1
/// (syntax validation) plus [`resolve_from_account`]. An invalid DID
/// yields an `invalidDid` error resolution (never a panic).
pub fn resolve_str(did: &str, account: Option<&RawAccount>) -> DidResolution {
    match BioDid::parse(did) {
        Ok(did) => resolve_from_account(&did, account),
        Err(e) => DidResolution::error(e.resolution_error_code()),
    }
}

/// A synchronous registry account fetcher (spec Section 6.2 step 5).
///
/// Implementations MUST return `Ok(None)` only when the account genuinely
/// does not exist at the queried commitment, and `Err` for every transport
/// or RPC failure. Resolvers SHOULD fetch at `finalized` commitment.
pub trait RegistryReader {
    /// Transport error type.
    type Error;

    /// Fetch the account at `address` (a PDA), or `None` if it does not
    /// exist.
    fn fetch_account(&self, address: &[u8; 32]) -> Result<Option<RawAccount>, Self::Error>;
}

/// An asynchronous registry account fetcher. Same contract as
/// [`RegistryReader`].
pub trait AsyncRegistryReader {
    /// Transport error type.
    type Error;

    /// Fetch the account at `address` (a PDA), or `None` if it does not
    /// exist.
    fn fetch_account(
        &self,
        address: &[u8; 32],
    ) -> impl core::future::Future<Output = Result<Option<RawAccount>, Self::Error>> + Send;
}

/// Full resolution via a synchronous fetcher: derive the PDA, fetch, and
/// run [`resolve_from_account`]. Transport errors propagate as `Err`.
#[cfg(feature = "pda")]
pub fn resolve_with<R: RegistryReader>(
    reader: &R,
    did: &BioDid,
) -> Result<DidResolution, R::Error> {
    let (address, _bump) = crate::pda::find_did_account_address(&did.subject);
    let account = reader.fetch_account(&address)?;
    Ok(resolve_from_account(did, account.as_ref()))
}

/// Full resolution via an asynchronous fetcher. Transport errors propagate
/// as `Err`.
#[cfg(feature = "pda")]
pub async fn resolve_with_async<R: AsyncRegistryReader>(
    reader: &R,
    did: &BioDid,
) -> Result<DidResolution, R::Error> {
    let (address, _bump) = crate::pda::find_did_account_address(&did.subject);
    let account = reader.fetch_account(&address).await?;
    Ok(resolve_from_account(did, account.as_ref()))
}
