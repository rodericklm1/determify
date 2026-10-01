"""
concurrency.py - Shared bounded parallel submission helper for Determify.

Stdlib-only. Both the per-finding triage path (scanner.py) and the deep chunk
path (deep_scanner.py) submit through this single gate so in-flight work is
bounded by the configured worker count instead of unbounded queueing.
"""

import concurrent.futures


def bounded_parallel_map(fn, items, max_workers):
    """
    Run fn(item) over items using at most max_workers threads and return
    results in input order.

    Guarantees:
    - At most max_workers futures are pending (submitted but unfinished) at any
      moment; further items are only submitted as earlier ones complete, so the
      helper never enqueues an unbounded backlog of network work.
    - Results are ordered by input position, never by completion order.
    - If any call raises, the first error is re-raised and every queued,
      not-yet-started submission is cancelled, so remaining unscheduled work
      never starts.

    Cancellation caveat: a request already handed to the network cannot be
    revoked; in-flight calls run to completion or until their own HTTP timeout
    before this function returns. Do not interpret cancellation as immediate
    abort of started requests.
    """
    items = list(items)
    n = len(items)
    if n == 0:
        return []
    workers = max(1, min(int(max_workers), n))
    results = [None] * n

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {}  # future -> input index
        next_idx = 0

        def _fill():
            nonlocal next_idx
            while next_idx < n and len(futures) < workers:
                futures[executor.submit(fn, items[next_idx])] = next_idx
                next_idx += 1

        _fill()
        first_error = None
        while futures:
            done, _ = concurrent.futures.wait(
                list(futures), return_when=concurrent.futures.FIRST_COMPLETED
            )
            for fut in done:
                idx = futures.pop(fut)
                if first_error is None:
                    try:
                        results[idx] = fut.result()
                    except BaseException as exc:  # noqa: BLE001 - captured and re-raised below
                        first_error = exc
                        # Cancel everything still queued or unsubmitted.
                        for pending in futures:
                            pending.cancel()
                else:
                    # Draining phase: never start new work; reap results of
                    # requests that were already in flight.
                    try:
                        fut.result()
                    except BaseException:
                        pass
            if first_error is None:
                _fill()

        if first_error is not None:
            raise first_error

    return results
