
from zephyr.core.charm import CharmRepository
from zephyr.core.model import Lifecycle
from zephyr.core.sync import DeltaStream, clone
from zephyr.server.api import Environment

from base import Base


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


class CloneTest(Base):

    def setUp(self):
        self.repo_dir = self.mkdir()
        self.charms = CharmRepository(self.repo_dir)
        self.env = Environment(charms=self.charms)
        self.write_local_charm({
            'name': 'mysql',
            'series': 'trusty',
            'provides': {
                'db': {
                    'scope': 'global',
                    'interface': 'mysql'}}})
        self.write_local_charm({
            'name': 'wordpress',
            'series': 'trusty',
            'requires': {
                'backend': {
                    'interface': 'mysql'}}})
        self.write_local_charm({
            'name': 'metrics',
            'series': 'trusty',
            'subordinate': True,
            'requires': {
                'host': {
                    'interface': 'juju-info'}}})

    def xtest_service_relation(self):
        self.env.deploy('db', 'local:trusty/mysql')
        self.env.deploy('blog', 'local:trusty/wordpress')
        self.env.add_relation('db', 'blog')
        self.env.add_unit('blog', count=3)
        env = clone(self.env)
        self.assertEqual(env.status(), {})
