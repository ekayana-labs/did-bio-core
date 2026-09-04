//! Identifier syntax and DID URL vectors (spec Section 4).

mod common;

use common::{example_did, EXAMPLE_DID, EXAMPLE_IDSTRING};
use did_bio_core::{BioDid, DidUrl, Error, Network};

#[test]
fn parses_all_network_forms() {
    let mainnet = BioDid::parse(&format!("did:bio:{EXAMPLE_IDSTRING}")).unwrap();
    assert_eq!(mainnet.network, Network::Mainnet);

    for (segment, network) in [
        ("devnet", Network::Devnet),
        ("testnet", Network::Testnet),
        ("localnet", Network::Localnet),
    ] {
        let did = BioDid::parse(&format!("did:bio:{segment}:{EXAMPLE_IDSTRING}")).unwrap();
        assert_eq!(did.network, network);
        assert_eq!(did.subject, mainnet.subject);
        // Section 4.2: DIDs differing only in network are distinct DIDs.
        assert_ne!(did.to_string(), mainnet.to_string());
    }
}

#[test]
fn display_roundtrips() {
    for did in [
        format!("did:bio:{EXAMPLE_IDSTRING}"),
        EXAMPLE_DID.to_string(),
        format!("did:bio:localnet:{EXAMPLE_IDSTRING}"),
        // 32 ones decode to 32 zero bytes: minimum length idstring.
        format!("did:bio:{}", "1".repeat(32)),
    ] {
        assert_eq!(BioDid::parse(&did).unwrap().to_string(), did);
    }
}

#[test]
fn rejects_invalid_dids() {
    let invalid = [
        // prefix violations (case sensitive, Section 4.3)
        format!("did:BIO:{EXAMPLE_IDSTRING}"),
        format!("DID:bio:{EXAMPLE_IDSTRING}"),
        format!("did:biox:{EXAMPLE_IDSTRING}"),
        "did:bio".to_string(),
        "did:bio:".to_string(),
        // network violations (Section 4.1: only devnet/testnet/localnet)
        format!("did:bio:mainnet:{EXAMPLE_IDSTRING}"),
        format!("did:bio:Devnet:{EXAMPLE_IDSTRING}"),
        format!("did:bio:goerli:{EXAMPLE_IDSTRING}"),
        format!("did:bio::{EXAMPLE_IDSTRING}"),
        format!("did:bio:devnet:devnet:{EXAMPLE_IDSTRING}"),
        // idstring charset (0, O, I, l excluded)
        format!("did:bio:0{}", &EXAMPLE_IDSTRING[1..]),
        format!("did:bio:O{}", &EXAMPLE_IDSTRING[1..]),
        format!("did:bio:I{}", &EXAMPLE_IDSTRING[1..]),
        format!("did:bio:l{}", &EXAMPLE_IDSTRING[1..]),
        format!("did:bio:{}+", &EXAMPLE_IDSTRING[..43]),
        // length bounds (32-44)
        format!("did:bio:{}", "2".repeat(31)),
        format!("did:bio:{}", "2".repeat(45)),
        // in range length that does not decode to 32 bytes
        format!("did:bio:{}", "z".repeat(44)),
        format!("did:bio:{}", "2".repeat(33)),
        // fragment is not part of a bare DID
        format!("{EXAMPLE_DID}#default"),
    ];
    for did in invalid {
        assert!(
            matches!(BioDid::parse(&did), Err(Error::InvalidDid(_))),
            "should reject: {did}"
        );
    }
}

#[test]
fn did_url_fragments() {
    let url = DidUrl::parse(&format!("{EXAMPLE_DID}#default")).unwrap();
    assert_eq!(url.did, example_did());
    assert_eq!(url.fragment.as_deref(), Some("default"));
    assert_eq!(url.to_string(), format!("{EXAMPLE_DID}#default"));

    assert_eq!(DidUrl::parse(EXAMPLE_DID).unwrap().fragment, None);

    for bad in [
        format!("{EXAMPLE_DID}#"),
        format!("{EXAMPLE_DID}#has space"),
        format!("{EXAMPLE_DID}#{}", "f".repeat(33)),
        format!("{EXAMPLE_DID}/path"),
        format!("{EXAMPLE_DID}?query=1"),
    ] {
        assert!(
            matches!(DidUrl::parse(&bad), Err(Error::InvalidDidUrl(_))),
            "should reject: {bad}"
        );
    }
}

#[test]
fn serde_did_as_string() {
    let did = example_did();
    let json = serde_json::to_string(&did).unwrap();
    assert_eq!(json, format!("\"{EXAMPLE_DID}\""));
    let back: BioDid = serde_json::from_str(&json).unwrap();
    assert_eq!(back, did);
    assert!(serde_json::from_str::<BioDid>("\"did:bio:nope\"").is_err());
}
