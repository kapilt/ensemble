

from ensemble.error import EnvError

from model import Lifecycle, Event


class DeltaStream(object):
    """The minimal set of events to represent the current environment state.
    """
    def __init__(self):
        self._events = []
        self.previous = {}

    def __iter__(self):
        return iter(self._events)

    def clear(self):
        self._events = []

    def consume(self, events):
        for e in events:
            self.add(e)
        return self

    def add(self, evt):
        found, found_idx = None, None
        for i, e in enumerate(self._events):
            if e.entity_id == evt.entity_id:
                found_idx = i
                found = e
                break
        if evt.change != Lifecycle.removed:
            self._events.append(evt)
        if found is None:
            self.previous[evt.entity_id] = None
            return
        if found.change in (Lifecycle.removed, Lifecycle.changed):
            p = self._events.pop(found_idx)
            self.previous[p.entity_id] = Event(
                p.type, p.change, p.entity_id, dict(p.data))

        if evt.type == 'annotation':
            found.data.update(evt.data)
            evt.data.clear()
            evt.data.update(found.data)


class WatchManager(object):

    def __init__(self):
        self.stream = DeltaStream()
        self.watches = {}
        self.watch_sequence = 0

    def notify(self, evt):
        self.stream.add(evt)
        for w in self.watches.values():
            w._notify(evt)

    def watch(self):
        wid = self.watch_sequence
        self.watch_sequence += 1
        self.watches[wid] = w = Watch(self, wid)
        return w


class Watch(object):
    """Approximation of a watch, since operations against in mem are
    instaneous, goal state should immediately appear in a watch.

    It does not serve as a continous watch, and must be periodically
    polled (via next). The entire mock api is intended for usage from
    single threaded contexts for a which blocking watch doesn't make
    sense.
    """
    def __init__(self, mgr, wid):
        self.mgr = mgr
        self.wid = wid
        self.running = False
        self.pending = None

    def noop(self):
        pass

    start = reconnect = noop

    def stop(self):
        if self.wid in self.mgr.watches:
            del self.mgr.watches[self.wid]

    def _notify(self, evt):
        if not self.running:
            return
        self.pending.append(evt)

    def next(self):
        if self.running is False:
            changes = list(self.mgr.stream)
            self.running = True
            self.pending = []
            return [[c.type, c.change, c.data] for c in changes]
        elif self.running is None:
            return EnvError({"Error": "Can't watch on closed watcher"})
        if self.pending:
            changes = self.pending[:]
            self.pending = []
            return [[c.type, c.change, c.data] for c in changes]

        raise StopIteration()

    def __iter__(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, exc, v, t):
        self.stop()
