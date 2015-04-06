from base import Base

from ..core.model import Lifecycle, Event
from ..core.watch import WatchManager, DeltaStream


class WatchManagerTest(Base):

    def setUp(self):
        self.watches = WatchManager()

    def test_watch(self):
        l = Lifecycle
        self.watches.notify(Event('machine', l.changed, '1', {'a': 1}))
        self.watches.notify(Event('machine', l.removed, '1', {'b': 1}))
        self.watches.notify(Event('service', l.changed, 'svc', {'b': 1}))
        self.watches.notify(Event('unit', l.changed, 'svc/0', {'c': 1}))
        w = self.watches.watch()

        events = iter(w)
        changes = events.next()
        self.assertEqual(changes, [
            ['service', l.changed, {'b': 1}],
            ['unit', l.changed, {'c': 1}]])

        self.watches.notify(Event('unit', l.changed, 'svc/0', {'c': 2}))
        changes = events.next()

        self.assertEqual(changes, [
            ['unit', l.changed, {'c': 2}]])

        self.watches.notify(Event('unit', l.removed, 'svc/0', {}))
        w2 = self.watches.watch()

        self.assertEqual(list(w2), [[['service', l.changed, {'b': 1}]]])

        changes = events.next()
        self.assertEqual(changes, [['unit', l.removed, {}]])


class DeltaStreamTest(Base):

    def test_reduce_entity(self):
        stream = DeltaStream()
        stream.add(Event('machine', Lifecycle.changed, '1', {'a': 1}))
        stream.add(Event('machine', Lifecycle.changed, '1', {'b': 2}))
        self.assertEqual(
            list(stream), [
                Event('machine', Lifecycle.changed, '1', {'b': 2})])

    def test_reduce_remove_entity(self):
        stream = DeltaStream()
        stream.add(Event('machine', Lifecycle.changed, '1', {'a': 1}))
        self.assertEqual(stream.previous['1'], None)
        stream.add(Event('machine', Lifecycle.removed, '1', {'b': 2}))
        self.assertEqual(list(stream), [])

    def test_reduce_annotation(self):
        stream = DeltaStream()
        stream.add(
            Event('annotation', Lifecycle.changed, 'service-foo', {'a': 1}))
        stream.add(
            Event('annotation', Lifecycle.changed, 'service-foo', {'b': 2}))
        self.assertEqual(
            list(stream), [
                Event(
                    'annotation', Lifecycle.changed, 'service-foo',
                    {'a': 1, 'b': 2})])

        self.assertEqual(
            stream.previous['service-foo'],
            Event('annotation', Lifecycle.changed, 'service-foo', {'a': 1}))
