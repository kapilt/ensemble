from base import Base

from ..core.charm import CharmRepository
from ..core.constraint import Constraints
from ..core.model import (
    Lifecycle,
    Machine,
    Network,
    Relation,
    Service,
    Unit)


class EventSerializationTest(Base):

    def setUp(self):
        self.net_a = Network('172.10.0.0', u'', 'public')
        self.net_b = Network('192.168.0.0', u'', 'private')
        self.repo_dir = self.mkdir()
        self.charms = CharmRepository(self.repo_dir)
        self.write_local_charm({
            'name': 'etcd',
            'series': 'trusty',
            'peers': {
                'cluster': {
                    'interface': 'etcd'}}})

    def _machine(self):
        m = Machine({
            'id': '1',
            'public_address': self.net_a.allocate_ipv4(),
            'private_address': self.net_b.allocate_ipv4(),
            'agent_version': '1.20.14',
            'series': 'trusty',
            'constraints': Constraints.actualize(
                {'mem': 2000, 'cpu-cores': 4}),
            'state': Lifecycle.started,
            'instance_state': Lifecycle.running})
        return m

    def test_machine_format(self):
        m = self._machine()
        evt = m.format_event()
        self.assertEqual(evt.entity_id, '1')
        for n in evt.data['Addresses']:
            n.pop('Value')
        self.assertEqual(evt.data, {
            u'Addresses': [{u'NetworkName': u'',
                            u'Scope': 'public',
                            u'Type': u'ipv4'},
                           {u'NetworkName': u'',
                            u'Scope': 'private',
                            u'Type': u'ipv4'}],
            u'HardwareCharacteristics': {u'Arch': u'amd64',
                                         u'CpuCores': 1,
                                         u'CpuPower': 100,
                                         u'Mem': 1740,
                                         u'RootDisk': 8192},
            u'Life': None,
            u'Series': 'trusty',
            u'Status': u'running',
            u'StatusData': None,
            u'StatusInfo': u'',
            u'SupportContainersKnown': True,
            u'SupportedContainers': ['lxc']})

    def test_service_format(self):
        charm = self.charms.get('local:trusty/etcd')
        s = Service({
            'name': unicode('db'),
            'subordinate': charm.subordinate,
            'charm_url': charm.charm_url,
            'charm': charm,
            'config': {},
            'constraints': Constraints.actualize(
                {'mem': 4000}),
            'machine_spec': None})
        evt = s.format_event()
        self.assertEqual(evt.entity_id, u'db')
        self.assertEqual(
            evt.data,
            {'CharmURL': 'local:trusty/etcd-0',
             'Config': {},
             'Constraints': {'mem': 4000},
             'Exposed': False,
             'MinUnits': 0,
             'Life': 'alive',
             'Name': 'db',
             'OwnerTag': 'user-admin'})

    def test_unit_format(self):
        u = Unit({
            'id': 'etcd/1',
            'state': Lifecycle.running,
            'private_address': self.net_b.allocate_ipv4(),
            'public_address': self.net_a.allocate_ipv4(),
            'charm_url': u'local:trusty/etcd',
            'series': 'trusty',
            'machine': '2',
            'agent_version': '1.20.10'})
        evt = u.format_event()
        self.assertEqual(evt.entity_id, 'etcd/1')
        del evt.data['PublicAddress']
        del evt.data['PrivateAddress']
        self.assertEqual(evt.data, {
            u'CharmURL': u'local:trusty/etcd',
            u'MachineId': '2',
            u'Name': 'etcd/1',
            u'Ports': [],
            u'Series': 'trusty',
            u'Service': 'etcd',
            u'StatusData': None,
            u'StatusInfo': u''})

    def test_relation_format(self):
        charm = self.charms.get('local:trusty/etcd')
        ep = [p for p in charm.endpoints if p['role'] == 'peer'][0]
        key = ('db:%s' % ep['name'])

        r = Relation({
            'key': key, 'id': 1, 'endpoints': [ep],
            'scope': 'global', 'interface': ep['interface']})

        evt = r.format_event()
        self.assertEqual(evt.entity_id, 1)
        self.assertEqual(evt.data, {
            'Endpoints': [{u'Limit': 1,
                           u'Name': u'cluster',
                           u'Optional': False,
                           u'Role': u'peer',
                           u'Scope': 'global'}],
            'Id': 1,
            'Key': u'db:cluster'})
