//// A first-in, first-out queue with amortised constant-time operations,
//// for the stores' insertion-ordered expiry and eviction.

import gleam/list

pub opaque type Fifo(a) {
  Fifo(front: List(a), back: List(a), size: Int)
}

pub fn new() -> Fifo(a) {
  Fifo([], [], 0)
}

pub fn push(queue: Fifo(a), item: a) -> Fifo(a) {
  Fifo(..queue, back: [item, ..queue.back], size: queue.size + 1)
}

/// The oldest item and the queue without it.
pub fn pop(queue: Fifo(a)) -> Result(#(a, Fifo(a)), Nil) {
  case queue {
    Fifo(front: [first, ..rest], back:, size:) ->
      Ok(#(first, Fifo(rest, back, size - 1)))
    Fifo(front: [], back: [], ..) -> Error(Nil)
    Fifo(front: [], back:, size:) -> pop(Fifo(list.reverse(back), [], size))
  }
}

pub fn size(queue: Fifo(a)) -> Int {
  queue.size
}
