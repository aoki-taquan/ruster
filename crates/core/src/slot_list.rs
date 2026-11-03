//! Intrusive doubly linked lists over caller-backed slot arrays.
//!
//! Each slot embeds a [`SlotLinks`] and the runtime keeps one [`SlotList`]
//! header per list. A slot is in at most one list at a time; the runtime
//! records which. Every operation is O(1), touches at most three slots, and
//! never allocates. The NAT44 runtimes use these lists to keep free slots in
//! index order and occupied slots in last-activity order, so a reusable slot
//! is found at a list head instead of by scanning the table (PERF-001).

pub(crate) const LINK_NONE: u32 = u32::MAX;

/// Previous and next slot of the list a slot is on (`LINK_NONE` at the ends
/// and when unlinked).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SlotLinks {
    prev: u32,
    next: u32,
}

impl SlotLinks {
    pub(crate) const UNLINKED: Self = Self {
        prev: LINK_NONE,
        next: LINK_NONE,
    };

    /// The next slot on the list (`LINK_NONE` at the tail or unlinked).
    pub(crate) const fn next_link(self) -> u32 {
        self.next
    }
}

impl Default for SlotLinks {
    fn default() -> Self {
        Self::UNLINKED
    }
}

/// A slot type that embeds [`SlotLinks`].
pub(crate) trait Linked {
    fn links(&self) -> SlotLinks;
    fn links_mut(&mut self) -> &mut SlotLinks;
}

/// Head, tail, and length of one intrusive list.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SlotList {
    head: u32,
    tail: u32,
    len: u32,
}

fn encode(index: usize) -> u32 {
    let link = u32::try_from(index).expect("validated slot capacity fits u32");
    debug_assert!(link != LINK_NONE);
    link
}

fn decode(link: u32) -> Option<usize> {
    (link != LINK_NONE).then_some(link as usize)
}

impl SlotList {
    pub(crate) const EMPTY: Self = Self {
        head: LINK_NONE,
        tail: LINK_NONE,
        len: 0,
    };

    pub(crate) fn head(self) -> Option<usize> {
        decode(self.head)
    }

    pub(crate) fn tail(self) -> Option<usize> {
        decode(self.tail)
    }

    #[cfg(test)]
    pub(crate) const fn from_raw_for_test(head: u32, tail: u32, len: u32) -> Self {
        Self { head, tail, len }
    }

    pub(crate) const fn len(self) -> usize {
        self.len as usize
    }

    /// Appends the unlinked slot `index` at the tail.
    pub(crate) fn push_back<T: Linked>(&mut self, slots: &mut [T], index: usize) {
        debug_assert!(slots[index].links() == SlotLinks::UNLINKED);
        let link = encode(index);
        *slots[index].links_mut() = SlotLinks {
            prev: self.tail,
            next: LINK_NONE,
        };
        match decode(self.tail) {
            Some(tail) => slots[tail].links_mut().next = link,
            None => self.head = link,
        }
        self.tail = link;
        self.len += 1;
    }

    /// Removes slot `index`, which must be on this list, and leaves it
    /// unlinked.
    pub(crate) fn unlink<T: Linked>(&mut self, slots: &mut [T], index: usize) {
        let links = slots[index].links();
        match decode(links.prev) {
            Some(prev) => slots[prev].links_mut().next = links.next,
            None => {
                debug_assert!(self.head == encode(index));
                self.head = links.next;
            }
        }
        match decode(links.next) {
            Some(next) => slots[next].links_mut().prev = links.prev,
            None => {
                debug_assert!(self.tail == encode(index));
                self.tail = links.prev;
            }
        }
        *slots[index].links_mut() = SlotLinks::UNLINKED;
        self.len -= 1;
    }

    /// Walks the list from the head (at most `len` steps), checking every
    /// back link, the tail, and the length, and calls `visit` on each slot
    /// in order. Returns false on any inconsistency or when `visit` does.
    /// Validation only.
    pub(crate) fn validate<T: Linked>(
        self,
        slots: &[T],
        mut visit: impl FnMut(usize) -> bool,
    ) -> bool {
        let mut prev = LINK_NONE;
        let mut current = self.head;
        for _ in 0..self.len {
            let Some(index) = decode(current) else {
                return false;
            };
            let Some(slot) = slots.get(index) else {
                return false;
            };
            if slot.links().prev != prev || !visit(index) {
                return false;
            }
            prev = current;
            current = slot.links().next;
        }
        current == LINK_NONE && self.tail == prev
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy, Default)]
    struct Slot {
        links: SlotLinks,
    }

    impl Linked for Slot {
        fn links(&self) -> SlotLinks {
            self.links
        }

        fn links_mut(&mut self) -> &mut SlotLinks {
            &mut self.links
        }
    }

    fn in_index_order(slots: &mut [Slot]) -> SlotList {
        let mut list = SlotList::EMPTY;
        for index in 0..slots.len() {
            list.push_back(slots, index);
        }
        list
    }

    fn order(list: SlotList, slots: &[Slot]) -> Vec<usize> {
        let mut seen = Vec::new();
        assert!(list.validate(slots, |index| {
            seen.push(index);
            true
        }));
        seen
    }

    #[test]
    fn lists_keep_order_and_conserve_slots_across_every_operation() {
        let mut slots = [Slot::default(); 5];
        let mut free = in_index_order(&mut slots);
        let mut used = SlotList::EMPTY;
        assert_eq!(order(free, &slots), [0, 1, 2, 3, 4]);
        assert_eq!(order(used, &slots), Vec::<usize>::new());

        // Head, middle, and tail removal, each pushed onto the other list.
        for index in [0, 2, 4] {
            free.unlink(&mut slots, index);
            used.push_back(&mut slots, index);
        }
        assert_eq!(order(free, &slots), [1, 3]);
        assert_eq!(order(used, &slots), [0, 2, 4]);
        assert_eq!((free.head(), free.tail()), (Some(1), Some(3)));
        assert_eq!((free.len(), used.len()), (2, 3));

        // Move-to-tail of the head and the middle.
        used.unlink(&mut slots, 0);
        used.push_back(&mut slots, 0);
        used.unlink(&mut slots, 4);
        used.push_back(&mut slots, 4);
        assert_eq!(order(used, &slots), [2, 0, 4]);

        // Drain both lists to empty.
        for index in [1, 3] {
            free.unlink(&mut slots, index);
        }
        for index in [0, 4, 2] {
            used.unlink(&mut slots, index);
        }
        assert_eq!((free, used), (SlotList::EMPTY, SlotList::EMPTY));
        assert!(slots.iter().all(|slot| slot.links == SlotLinks::UNLINKED));
        assert_eq!(in_index_order(&mut []), SlotList::EMPTY);
    }

    #[test]
    fn validation_rejects_broken_links() {
        let mut slots = [Slot::default(); 3];
        let list = in_index_order(&mut slots);
        slots[1].links.prev = 2;
        assert!(!list.validate(&slots, |_| true));
        let mut slots = [Slot::default(); 3];
        let list = in_index_order(&mut slots);
        slots[2].links.next = 0;
        assert!(!list.validate(&slots, |_| true));
        let mut slots = [Slot::default(); 3];
        let list = in_index_order(&mut slots);
        assert!(!list.validate(&slots, |index| index != 1));
    }
}
