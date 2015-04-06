import unittest

from base import Base, TEST_OFFLINE

from ..core.env import Environment
from ..core.charm import CharmRepository
#from ..core.model import Service

from ..error import EnvError


class EnvironmentTest(Base):

    def setUp(self):
        self.repo_dir = self.mkdir()
        self.charms = CharmRepository(self.repo_dir)
        self.env = Environment(charms=self.charms)

    def test_add_remove_machine(self):
        result = self.env.add_machine(u'trusty', {'mem': 2000})
        self.assertEqual(result, {'Machine': '0', 'Error': None})
        m = self.env.status()['Machines']['0']
        self.assertTrue(m.pop('DNSName').startswith('172.10.'))
        self.assertEqual(m, {
            u'Agent': {u'Data': {},
                       u'Err': None,
                       u'Info': u'',
                       u'Life': u'',
                       u'Status': u'started',
                       u'Version': u'1.20.14'},
            u'AgentState': u'started',
            u'AgentStateInfo': u'',
            u'AgentVersion': u'1.20.14',
            u'Containers': {},
            u'Err': None,
            u'Id': u'0',
            u'InstanceId': u'i-0',
            u'InstanceState': u'running',
            u'Jobs': [u'JobHostUnits'],
            u'Life': u'',
            u'Series': u'trusty'})
        self.env.destroy_machines(['0'])
        self.assertFalse(self.env.status()['Machines'])

    def test_add_remove_container(self):
        mid = self.env.add_machine(u'trusty', {'mem': 2000})['Machine']
        cid = self.env.add_machine(
            'trusty', machine_spec='kvm:%s' % mid)['Machine']
        # Nested container
        ccid = self.env.add_machine(
            'trusty', machine_spec='lxc:%s' % cid)['Machine']
        self.assertEqual(
            (u'0', u'0/kvm/0', '0/kvm/0/lxc/0'),
            (mid, cid, ccid))
        status = self.env.status()['Machines']['0']
        self.assertEqual(
            status['Containers'].keys(), [cid])
        status = status['Containers'][cid]
        self.assertEqual(
            status['Containers'].keys(), [ccid])

    def test_remove_machine_with_unit(self):
        self.write_local_charm({
            'name': 'mysql',
            'series': 'trusty',
            'provides': {
                'db': {
                    'scope': 'global',
                    'interface': 'mysql'}}})
        self.env.deploy('db', 'local:trusty/mysql')
        self.assertRaises(
            EnvError,
            self.env.destroy_machines, ['0'])

        self.env.destroy_machines(['0'], force=True)
        self.assertEqual(
            self.env.status()['Services']['db']['Units'].keys(),
            [])

    def test_deploy_uses_extant(self):
        self.write_local_charm({
            'name': 'mysql',
            'series': 'trusty',
            'provides': {
                'db': {
                    'scope': 'global',
                    'interface': 'mysql'}}})
        self.env.add_machine('trusty', constraints={'mem': 2000})
        self.env.add_machine('trusty', constraints={'mem': 10000})
        self.env.add_machine(
            'trusty', constraints={'mem': 3000}, machine_spec="lxc:1")
        self.env.add_machine('trusty', constraints={'mem': 4000})
        self.env.deploy(
            'db', 'local:trusty/mysql', constraints={'mem': 3000})

        self.assertEqual(
            self.env.status()['Services']['db']['Units']['db/0']['Machine'],
            '1/lxc/0')

    def test_subordinate(self):
        self.write_local_charm({
            'name': 'mysql',
            'series': 'trusty',
            'provides': {
                'db': {
                    'interface': 'mysql'}}})
        self.write_local_charm({
            'name': 'monitor',
            'series': 'trusty',
            'subordinate': True,
            'requires': {
                'metrics': {
                    'scope': 'container',
                    'interface': 'juju-info'}}})
        self.env.deploy('monitor', 'local:trusty/monitor')
        status = self.env.status()
        self.assertFalse(status['Machines'])
        self.assertFalse(status['Services']['monitor']['Units'])
        self.env.deploy('db', 'local:trusty/mysql')

        self.env.add_relation('db', 'monitor')
        status = self.env.status()
        self.assertFalse(status['Services']['monitor']['Units'])
        subs = status['Services']['db']['Units']['db/0']['Subordinates']
        self.assertEqual(subs.keys(), ['monitor/0'])
        self.assertEqual(
            status['Services']['monitor']['SubordinateTo'],
            ['db'])

        self.env.remove_units(['db/0'])
        # verifying internal state
        self.assertFalse(self.env.env_get_service('monitor').units)

    def test_deploy_auto_adds_peer_rels(self):
        self.write_local_charm({
            'name': 'etcd',
            'series': 'trusty',
            'peers': {
                'cluster': {
                    'interface': 'reprap'}}})
        self.env.deploy('db', 'local:trusty/etcd')
        self.assertEqual(
            self.env.status()['Relations'],
            [{'Endpoints': [
                {'Name': 'cluster',
                 'Role': 'peer',
                 'ServiceName': 'db',
                 'Subordinate': False}],
              'Id': 0,
              'Interface': 'reprap',
              'Scope': 'global',
              'Key': 'db:cluster'}])

    def test_deploy_add_unit_with_placement(self):
        self.write_local_charm({
            'name': 'mysql',
            'series': 'trusty',
            'provides': {
                'db': {
                    'scope': 'global',
                    'interface': 'mysql'}}})
        self.env.add_machine('trusty')

        # Directly to machine
        self.env.deploy('db', 'local:trusty/mysql', machine_spec='0')

        # To machine with new container
        self.env.add_unit('db', machine_spec='lxc:0')

        self.assertEqual(
            sorted([(k, v['Machine']) for k, v in
                   self.env.status()['Services']['db']['Units'].items()]),
            [('db/0', '0'), ('db/1', '0/lxc/0')])

    def test_deploy_local_charm(self):
        self.write_local_charm({
            'name': 'mysql',
            'series': 'trusty',
            'provides': {
                'db': {
                    'scope': 'global',
                    'interface': 'mysql'}}})
        self.env.deploy('db', 'local:trusty/mysql')
        svc_info = self.env.status()['Services']['db']
        addr = svc_info['Units']['db/0'].pop('PublicAddress')
        self.assertTrue(addr.startswith('172.10.'))
        self.assertEqual(svc_info, {
            u'Charm': 'local:trusty/mysql-0',
            u'Err': None,
            u'Exposed': False,
            u'Life': u'',
            u'Networks': {u'Disabled': None, u'Enabled': None},
            u'Relations': {},
            u'SubordinateTo': [],
            u'Units': {u'db/0': {u'Agent': {u'Data': {},
                                            u'Err': None,
                                            u'Info': u'',
                                            u'Life': u'',
                                            u'Status': u'started',
                                            u'Version': u'1.20.14'},
                                 u'AgentState': u'started',
                                 u'AgentStateInfo': u'',
                                 u'AgentVersion': u'1.20.14',
                                 u'Charm': u'',
                                 u'Err': None,
                                 u'Life': u'',
                                 u'Machine': u'0',
                                 u'OpenedPorts': [],
                                 u'Subordinates': None}}})

    @unittest.skipIf(TEST_OFFLINE, "Requires network access to charm store")
    def test_deploy_service(self):
        self.charms.add_charm('cs:~hazmat/precise/docker-0')
        self.env.deploy('docker', 'cs:~hazmat/precise/docker-0')
        svc_info = self.env.status()['Services']['docker']
        addr = svc_info['Units']['docker/0'].pop('PublicAddress')
        self.assertTrue(addr.startswith('172.10.'))
        self.assertEqual(
            svc_info,
            {u'Charm': u'cs:~hazmat/precise/docker-0',
             u'Err': None,
             u'Exposed': False,
             u'Life': u'',
             u'Networks': {u'Disabled': None, u'Enabled': None},
             u'Relations': {},
             u'SubordinateTo': [],
             u'Units': {u'docker/0': {u'Agent': {u'Data': {},
                                                 u'Err': None,
                                                 u'Info': u'',
                                                 u'Life': u'',
                                                 u'Status': u'started',
                                                 u'Version': u'1.20.14'},
                                      u'AgentState': u'started',
                                      u'AgentStateInfo': u'',
                                      u'AgentVersion': u'1.20.14',
                                      u'Charm': u'',
                                      u'Err': None,
                                      u'Life': u'',
                                      u'Machine': u'0',
                                      u'OpenedPorts': [],
                                      u'Subordinates': None}}})

    @unittest.skipIf(TEST_OFFLINE, "Requires network access to charm store")
    def test_upgrade_service(self):
        self.write_local_charm({
            'name': 'etcd',
            'series': 'trusty',
            'peers': {
                'cluster': {'interface': 'etcd-raft'}}})
        self.charms.add_charm('cs:~hazmat/trusty/etcd-5')

        self.env.deploy('etcd', 'cs:~hazmat/trusty/etcd-5')
        self.assertRaises(
            EnvError, self.env.set_charm, 'etcd', 'local:trusty/etcd')

        self.charms.add_charm('cs:~hazmat/trusty/etcd-6')
        self.env.set_charm('etcd', 'cs:~hazmat/trusty/etcd-6')
        svc = self.env.env_get_service('etcd')
        self.assertEqual(svc.charm_url, 'cs:~hazmat/trusty/etcd-6')

        self.env.set_charm('etcd', 'local:trusty/etcd', force=True)
        self.assertEqual(svc.charm_url, 'local:trusty/etcd-1')

    def test_add_remove_relation(self):
        self.write_local_charm({
            'name': 'mysql',
            'series': 'trusty',
            'provides': {
                'client': {
                    'interface': 'mysql'}}})
        self.write_local_charm({
            'name': 'wordpress',
            'series': 'trusty',
            'requires': {
                'backend': {
                    'scope': 'global',
                    'interface': 'mysql'}}})
        self.env.deploy('db', 'local:trusty/mysql')
        self.env.deploy('blog', 'local:trusty/wordpress')
        result = self.env.add_relation('db', 'blog')
        self.assertEqual(
            result,
            {'Endpoints': {
                u'blog': {u'Interface': 'mysql',
                          u'Limit': None,
                          u'Name': u'backend',
                          u'Optional': False,
                          u'Role': u'requirer',
                          u'Scope': 'global'},
                u'db': {u'Interface': 'mysql',
                        u'Limit': None,
                        u'Name': u'client',
                        u'Optional': False,
                        u'Role': u'provider',
                        u'Scope': 'global'}}})
        self.assertEqual(
            self.env.status()['Relations'],
            [{u'Interface': 'mysql', u'Scope': u'global', 'Id': 0,
              u'Key': u'blog:backend db:client',
              u'Endpoints': [
                  {u'ServiceName': u'db', u'Role': u'provider',
                   u'Name': u'client', 'Subordinate': False},
                  {u'ServiceName': u'blog', u'Role': u'requirer',
                   u'Name': u'backend', 'Subordinate': False}]}])
        self.env.remove_relation('blog', 'db')
        self.assertFalse(self.env.status()['Relations'])

    def test_annotations(self):
        self.env.add_machine('trusty')
        self.assertEqual(
            self.env.set_annotation('0', 'machine', {'owner': 'hazmat'}),
            {})
        self.assertEqual(
            self.env.get_annotation('0', 'machine'),
            {'Annotations': {'owner': 'hazmat'}})
