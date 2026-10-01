//! A quorum over several registry readers (spec Section 7).

mod common;

use common::{example_did, registry_account, rich_account_image};
use did_bio_core::{AsyncRegistryReader, Quorum, RawAccount, RegistryReader};

/// A reader that gives one fixed answer.
struct Fixed {
    answer: Result<Option<RawAccount>, &'static str>,
}

fn fixed(answer: Result<Option<RawAccount>, &'static str>) -> Fixed {
    Fixed { answer }
}

impl RegistryReader for Fixed {
    type Error = &'static str;

    fn fetch_account(&self, _: &[u8; 32]) -> Result<Option<RawAccount>, &'static str> {
        self.answer.clone()
    }
}

impl AsyncRegistryReader for Fixed {
    type Error = &'static str;

    async fn fetch_account(&self, address: &[u8; 32]) -> Result<Option<RawAccount>, &'static str> {
        RegistryReader::fetch_account(self, address)
    }
}

fn account() -> RawAccount {
    registry_account(rich_account_image(&example_did().subject))
}

#[test]
fn thresholds_must_be_a_majority() {
    assert!(Quorum::new(Vec::<Fixed>::new(), 0).is_none());
    assert!(Quorum::<Fixed>::majority(Vec::new()).is_none());
    let three = || (0..3).map(|_| fixed(Ok(None))).collect::<Vec<_>>();
    assert!(Quorum::new(three(), 1).is_none());
    assert!(Quorum::new(three(), 4).is_none());
    assert_eq!(Quorum::new(three(), 2).unwrap().threshold(), 2);
    assert_eq!(Quorum::majority(three()).unwrap().threshold(), 2);
}

#[test]
fn one_withholding_node_is_outvoted() {
    let quorum = Quorum::majority(vec![
        fixed(Ok(Some(account()))),
        fixed(Ok(None)),
        fixed(Ok(Some(account()))),
    ])
    .unwrap();
    assert_eq!(
        RegistryReader::fetch_account(&quorum, &[0; 32]),
        Ok(Some(account()))
    );
}

#[cfg(feature = "pda")]
#[test]
fn the_drivers_read_through_a_quorum() {
    use core::future::Future;
    use core::pin::pin;
    use core::task::{Context, Poll, Waker};

    let quorum = Quorum::majority(vec![
        fixed(Ok(None)),
        fixed(Ok(Some(account()))),
        fixed(Ok(Some(account()))),
    ])
    .unwrap();
    let did = example_did();
    let resolution = did_bio_core::resolve_with(&quorum, &did).unwrap();
    assert_eq!(
        resolution.document_metadata.version_id.as_deref(),
        Some("7")
    );

    let mut future = pin!(did_bio_core::resolve_with_async(&quorum, &did));
    let Poll::Ready(resolution) = future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    else {
        panic!("the readers never suspend");
    };
    assert_eq!(
        resolution.unwrap().document_metadata.version_id.as_deref(),
        Some("7")
    );
}

#[test]
fn a_majority_decides_absence_as_well() {
    let quorum = Quorum::majority(vec![
        fixed(Ok(None)),
        fixed(Ok(Some(account()))),
        fixed(Ok(None)),
    ])
    .unwrap();
    assert_eq!(RegistryReader::fetch_account(&quorum, &[0; 32]), Ok(None));
}

#[test]
fn failures_and_splits_give_no_answer() {
    let quorum = Quorum::majority(vec![
        fixed(Err("timeout")),
        fixed(Ok(Some(account()))),
        fixed(Err("refused")),
    ])
    .unwrap();
    let error = RegistryReader::fetch_account(&quorum, &[0; 32]).unwrap_err();
    assert_eq!(error.failures, vec![(0, "timeout"), (2, "refused")]);
    assert_eq!((error.agreeing, error.threshold), (1, 2));
    assert_eq!(
        error.to_string(),
        "no quorum: 1 of the 2 readers needed agreed; reader 0 failed: timeout; reader 2 failed: refused"
    );

    let mut other = account();
    other.data.push(0);
    let split = Quorum::majority(vec![
        fixed(Ok(Some(account()))),
        fixed(Ok(Some(other))),
        fixed(Ok(None)),
    ])
    .unwrap();
    assert_eq!(
        RegistryReader::fetch_account(&split, &[0; 32])
            .unwrap_err()
            .agreeing,
        1
    );
}
