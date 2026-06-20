use std::time::Duration;

use tokio::{sync::mpsc, time::timeout};

use crate::runtime::RuntimeError;

#[derive(Debug, Clone)]
pub struct KernelEventSender<T> {
    sender: mpsc::Sender<T>,
}

impl<T> KernelEventSender<T> {
    /// Sends an event without waiting for channel capacity.
    ///
    /// # Errors
    ///
    /// Returns the event when the bounded channel is full or closed.
    pub fn try_send(&self, event: T) -> Result<(), mpsc::error::TrySendError<T>> {
        self.sender.try_send(event)
    }

    #[must_use]
    pub fn capacity(&self) -> usize {
        self.sender.capacity()
    }
}

#[derive(Debug)]
pub struct KernelEventReceiver<T> {
    receiver: mpsc::Receiver<T>,
}

impl<T> KernelEventReceiver<T> {
    pub async fn recv(&mut self) -> Option<T> {
        self.receiver.recv().await
    }

    /// Closes the receiver and drains queued events before the timeout.
    ///
    /// # Errors
    ///
    /// Returns an error when queued events are not drained before `timeout`.
    pub async fn drain_with_timeout(&mut self, duration: Duration) -> Result<usize, RuntimeError> {
        self.receiver.close();

        timeout(duration, async {
            let mut drained = 0usize;
            while self.receiver.recv().await.is_some() {
                drained = drained.saturating_add(1);
            }
            drained
        })
        .await
        .map_err(|_| RuntimeError::QueueDrainTimeout { timeout: duration })
    }
}

#[must_use]
pub fn bounded_kernel_events<T>(capacity: usize) -> (KernelEventSender<T>, KernelEventReceiver<T>) {
    let (sender, receiver) = mpsc::channel(capacity);

    (
        KernelEventSender { sender },
        KernelEventReceiver { receiver },
    )
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn kernel_event_channel_is_bounded() {
        let (sender, _receiver) = bounded_kernel_events::<u64>(2);

        assert!(sender.try_send(1).is_ok());
        assert!(sender.try_send(2).is_ok());
        assert!(sender.try_send(3).is_err());
    }

    #[tokio::test]
    async fn receiver_drains_queued_events() {
        let (sender, mut receiver) = bounded_kernel_events::<u64>(2);
        sender.try_send(1).expect("first event should queue");
        sender.try_send(2).expect("second event should queue");
        drop(sender);

        let drained = receiver
            .drain_with_timeout(Duration::from_millis(100))
            .await
            .expect("queue should drain");

        assert_eq!(drained, 2);
    }
}
