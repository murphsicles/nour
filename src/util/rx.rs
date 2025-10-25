//! Lightweight reactive library for event handling in Bitcoin SV toolkit.
use crate::util::{Error, Result};
use std::sync::{Arc, RwLock, TryLockError, Weak};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::Duration;
/// Observes an event of type T.
pub trait Observer<T>: Sync + Send {
    /// Called when the event occurs.
    fn next(&self, event: &T);
}
/// Event publisher that may be subscribed to.
pub trait Observable<T: Send + Sync + Clone + 'static> {
    /// Adds a weakly held observer.
    fn subscribe<S: Observer<T> + 'static>(&self, observer: &Arc<S>);
    /// Waits indefinitely for an event to be emitted.
    #[must_use]
    fn poll(&self) -> T {
        let (poller, rx) = Poller::new();
        self.subscribe(&poller);
        rx.recv().unwrap()
    }
    /// Waits for an event to be emitted with a timeout.
    #[must_use]
    fn poll_timeout(&self, duration: Duration) -> Result<T> {
        let (poller, rx) = Poller::new();
        self.subscribe(&poller);
        rx.recv_timeout(duration).map_err(|_| Error::Timeout)
    }
}
/// Stores the observers for a particular event.
pub struct Subject<T> {
    observers: RwLock<Vec<Weak<dyn Observer<T>>>>,
    pending: RwLock<Vec<Weak<dyn Observer<T>>>>,
}
impl<T> Subject<T> {
    /// Creates a new empty set of observers.
    #[must_use]
    pub fn new() -> Self {
        Self {
            observers: RwLock::new(Vec::new()),
            pending: RwLock::new(Vec::new()),
        }
    }
}
impl<T: Send + Sync + Clone> Observer<T> for Subject<T> {
    fn next(&self, event: &T) {
        let mut any_to_remove = false;
        {
            for observer in self.observers.read().unwrap().iter() {
                if let Some(observer) = observer.upgrade() {
                    observer.next(event);
                } else {
                    any_to_remove = true;
                }
            }
        }
        if any_to_remove {
            let mut observers = self.observers.write().unwrap();
            observers.retain(|observer| observer.upgrade().is_some());
        }
        let any_pending = !self.pending.read().unwrap().is_empty();
        if any_pending {
            let mut observers = self.observers.write().unwrap();
            let mut pending = self.pending.write().unwrap();
            observers.append(&mut pending);
        }
    }
}
impl<T: Send + Sync + Clone + 'static> Observable<T> for Subject<T> {
    fn subscribe<S: Observer<T> + 'static>(&self, observer: &Arc<S>) {
        let weak_observer = Arc::downgrade(observer) as Weak<dyn Observer<T>>;
        match self.observers.try_write() {
            Ok(mut observers) => observers.push(weak_observer),
            Err(TryLockError::WouldBlock) => {
                self.pending.write().unwrap().push(weak_observer);
            }
            Err(TryLockError::Poisoned(_)) => panic!("Observer lock poisoned"),
        }
    }
}
/// A subject that only emits a single value.
///
/// After a value is emitted once, all future calls to next() will be ignored,
/// and any future subscriptions will be called with the original value once.
pub struct Single<T: Sync + Send + Clone> {
    subject: Subject<T>,
    value: RwLock<Option<T>>,
}
impl<T: Sync + Send + Clone> Single<T> {
    /// Creates a new single with an empty set of observers.
    #[must_use]
    pub fn new() -> Self {
        Self {
            subject: Subject::new(),
            value: RwLock::new(None),
        }
    }
}
impl<T: Sync + Send + Clone> Observer<T> for Single<T> {
    fn next(&self, event: &T) {
        let mut value = self.value.write().unwrap();
        if value.is_none() {
            *value = Some(event.clone());
            self.subject.next(event);
        }
    }
}
impl<T: Sync + Send + Clone + 'static> Observable<T> for Single<T> {
    fn subscribe<S: Observer<T> + 'static>(&self, observer: &Arc<S>) {
        match &*self.value.read().unwrap() {
            Some(value) => observer.next(value),
            None => self.subject.subscribe(observer),
        }
    }
}
struct Poller<T: Sync + Send + Clone> {
    sender: Sender<T>,
}
impl<T: Sync + Send + Clone> Poller<T> {
    pub fn new() -> (Arc<Poller<T>>, Receiver<T>) {
        let (tx, rx) = channel();
        (Arc::new(Poller { sender: tx }), rx)
    }
}
impl<T: Sync + Send + Clone> Observer<T> for Poller<T> {
    fn next(&self, event: &T) {
        self.sender.send(event.clone()).ok();
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use pretty_assertions::assert_eq;
    #[test]
    fn publish_observe() {
        struct MyObserver {
            observed: AtomicBool,
        }
        impl Observer<u32> for MyObserver {
            fn next(&self, _event: &u32) {
                self.observed.store(true, Ordering::Relaxed);
            }
        }
        let subject = Subject::<u32>::new();
        let observer = Arc::new(MyObserver {
            observed: AtomicBool::new(false),
        });
        subject.subscribe(&observer);
        assert!(!observer.observed.load(Ordering::Relaxed));
        subject.next(&1);
        assert!(observer.observed.load(Ordering::Relaxed));
    }
    #[test]
    fn observe_during_next() {
        let subject = Arc::new(Subject::<u32>::new());
        struct MyObserver {
            subject: Arc<Subject<u32>>,
        }
        impl Observer<u32> for MyObserver {
            fn next(&self, _event: &u32) {
                self.subject.subscribe(&Arc::new(MyObserver {
                    subject: self.subject.clone(),
                }));
            }
        }
        subject.subscribe(&Arc::new(MyObserver {
            subject: subject.clone(),
        }));
        subject.next(&1);
    }
    #[test]
    fn single() {
        struct MyObserver {
            observed: AtomicBool,
        }
        impl Observer<u32> for MyObserver {
            fn next(&self, event: &u32) {
                assert_eq!(event, &5);
                assert!(!self.observed.swap(true, Ordering::Relaxed));
            }
        }
        let pre_emit_observer = Arc::new(MyObserver {
            observed: AtomicBool::new(false),
        });
        let post_emit_observer = Arc::new(MyObserver {
            observed: AtomicBool::new(false),
        });
        let single = Single::<u32>::new();
        single.subscribe(&pre_emit_observer);
        single.next(&5);
        assert!(pre_emit_observer.observed.load(Ordering::Relaxed));
        single.subscribe(&post_emit_observer);
        assert!(post_emit_observer.observed.load(Ordering::Relaxed));
        single.next(&6);
    }
}
