//! A registry reader that asks several readers and accepts an answer only
//! when a majority of them agree.
//!
//! An RPC node can withhold a registry account so that a resolver falls
//! back to the generative document, which hides a rotation or a
//! deactivation (spec Section 7). Asking independent providers and
//! comparing their answers means the attack needs a majority of them. An
//! absent account is an answer like any other, so withholding needs the
//! same majority.

use core::fmt;

use crate::resolve::{AsyncRegistryReader, RawAccount, RegistryReader};

/// Reads through every reader and returns the account that more than half
/// of them returned identically.
#[derive(Debug, Clone)]
pub struct Quorum<R> {
    readers: Vec<R>,
    threshold: usize,
}

impl<R> Quorum<R> {
    /// A quorum that needs `threshold` readers to agree. `None` unless the
    /// threshold is more than half of the readers and at most all of them,
    /// so two different answers can never both win.
    pub fn new(readers: Vec<R>, threshold: usize) -> Option<Self> {
        (threshold > readers.len() / 2 && threshold <= readers.len())
            .then_some(Self { readers, threshold })
    }

    /// A quorum that needs a simple majority. `None` without readers.
    pub fn majority(readers: Vec<R>) -> Option<Self> {
        let threshold = readers.len() / 2 + 1;
        Self::new(readers, threshold)
    }

    /// How many readers must agree.
    pub fn threshold(&self) -> usize {
        self.threshold
    }
}

/// Why a quorum gave no answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuorumError<E> {
    /// The readers that failed, by position, with their errors.
    pub failures: Vec<(usize, E)>,
    /// How many readers returned the most common answer.
    pub agreeing: usize,
    /// How many had to.
    pub threshold: usize,
}

impl<E: fmt::Display> fmt::Display for QuorumError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "no quorum: {} of the {} readers needed agreed",
            self.agreeing, self.threshold
        )?;
        for (i, error) in &self.failures {
            write!(f, "; reader {i} failed: {error}")?;
        }
        Ok(())
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for QuorumError<E> {}

/// The answers so far, each with the number of readers that gave it.
struct Tally<E> {
    answers: Vec<(Option<RawAccount>, usize)>,
    failures: Vec<(usize, E)>,
    threshold: usize,
}

impl<E> Tally<E> {
    fn new(threshold: usize) -> Self {
        Self {
            answers: Vec::new(),
            failures: Vec::new(),
            threshold,
        }
    }

    fn add(&mut self, reader: usize, answer: Result<Option<RawAccount>, E>) {
        match answer {
            Ok(answer) => match self.answers.iter_mut().find(|(seen, _)| *seen == answer) {
                Some((_, count)) => *count += 1,
                None => self.answers.push((answer, 1)),
            },
            Err(error) => self.failures.push((reader, error)),
        }
    }

    fn finish(self) -> Result<Option<RawAccount>, QuorumError<E>> {
        let agreeing = self
            .answers
            .iter()
            .map(|(_, count)| *count)
            .max()
            .unwrap_or(0);
        match self
            .answers
            .into_iter()
            .find(|(_, count)| *count >= self.threshold)
        {
            Some((answer, _)) => Ok(answer),
            None => Err(QuorumError {
                failures: self.failures,
                agreeing,
                threshold: self.threshold,
            }),
        }
    }
}

impl<R: RegistryReader> RegistryReader for Quorum<R> {
    type Error = QuorumError<R::Error>;

    fn fetch_account(&self, address: &[u8; 32]) -> Result<Option<RawAccount>, Self::Error> {
        let mut tally = Tally::new(self.threshold);
        for (i, reader) in self.readers.iter().enumerate() {
            tally.add(i, RegistryReader::fetch_account(reader, address));
        }
        tally.finish()
    }
}

/// The readers are asked one after another, so the quorum adds no runtime
/// dependency.
impl<R> AsyncRegistryReader for Quorum<R>
where
    R: AsyncRegistryReader + Sync,
    R::Error: Send,
{
    type Error = QuorumError<R::Error>;

    fn fetch_account(
        &self,
        address: &[u8; 32],
    ) -> impl core::future::Future<Output = Result<Option<RawAccount>, Self::Error>> + Send {
        let address = *address;
        async move {
            let mut tally = Tally::new(self.threshold);
            for (i, reader) in self.readers.iter().enumerate() {
                tally.add(
                    i,
                    AsyncRegistryReader::fetch_account(reader, &address).await,
                );
            }
            tally.finish()
        }
    }
}
