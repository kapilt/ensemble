# -*- coding: latin-1 -*-
# ensemble
#
# Copyright © Kapil Thangavelu
# Author: Kapil Thangavelu <kapil.foss@gmail.com>
#
# See COPYING file for details.
#
import os
import pprint
import shutil
import tempfile
import unittest

from ensemble.ensemble import (
    Environment, CharmRepository, Service, EndpointSolver, Constraints,
    Network, Machine, Unit, Relation, Lifecycle,
    DeltaStream, WatchManager, Event, clone,
    parse_charm_url,
    CharmURLError, EnvError, ConstraintError, yaml_dump)

TEST_OFFLINE = ("DEB_BUILD_ARCH" in os.environ or "TEST_OFFLINE" in os.environ)


class Base(unittest.TestCase):

    def mkdir(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        return d

    def change_environment(self, **kw):
        """
        """
        original_environ = dict(os.environ)

        @self.addCleanup
        def cleanup_env():
            os.environ.clear()
            os.environ.update(original_environ)

        os.environ.update(kw)

    def write_local_charm(self, md, config=None, actions=None):
        charm_dir = os.path.join(self.repo_dir, md['series'], md['name'])
        if not os.path.exists(charm_dir):
            os.makedirs(charm_dir)
        md_path = os.path.join(charm_dir, 'metadata.yaml')
        with open(md_path, 'w') as fh:
            fh.write(yaml_dump(md))

        if config is not None:
            cfg_path = os.path.join(charm_dir, 'config.yaml')
            with open(cfg_path, 'w') as fh:
                fh.write(yaml_dump(config))

        if actions is not None:
            act_path = os.path.join(charm_dir, 'actions.yaml')
            with open(act_path, 'w') as fh:
                fh.write(yaml_dump(actions))

    def pprint(self, d):
        pprint.pprint(d)


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


class CharmURLTest(Base):

    def assert_url(self, url, schema, user, series, name, rev):
        self.assertEquals(url.scheme, schema)
        self.assertEquals(url.user, user)
        self.assertEquals(url.series, series)
        self.assertEquals(url.name, name)
        self.assertEquals(url.revision, rev)

    def assert_error(self, err, url_str, message):
        self.assertEquals(
            str(err), "Bad charm URL %r: %s" % (url_str, message))

    def assert_parse(self, string, schema, user, series, name, rev):
        url = parse_charm_url(string)
        self.assert_url(url, schema, user, series, name, rev)
        #self.assertEquals(str(url), string)
        #self.assertEquals(url.path, string.split(":", 1)[1])

    def test_parse(self):
        self.assert_parse(
            "series/name-1", "cs", None, "series", "name", 1)
        self.assert_parse(
            "cs:~user/series/name", "cs", "user", "series", "name", None)
        self.assert_parse(
            "cs:~user/series/name-0", "cs", "user", "series", "name", 0)
        self.assert_parse(
            "cs:series/name", "cs", None, "series", "name", None)
        self.assert_parse(
            "cs:series/name-0", "cs", None, "series", "name", 0)
        self.assert_parse(
            "cs:series/name0", "cs", None, "series", "name0", None)
        self.assert_parse(
            "cs:series/n0-0n-n0", "cs", None, "series", "n0-0n-n0", None)
        self.assert_parse(
            "local:series/name", "local", None, "series", "name", None)
        self.assert_parse(
            "local:series/name-0", "local", None, "series", "name", 0)
        #self.assert_cannot_parse(
        #    "cs:name", "invalid form")

    def assert_cannot_parse(self, string, message):
        self.assertRaises(CharmURLError, parse_charm_url, string)

    def test_cannot_parse(self):
        self.assert_cannot_parse(
            "bs:~user/series/name-1", "invalid schema")
        self.assert_cannot_parse(
            "cs:~user/1/name-1", "invalid series")
        self.assert_cannot_parse(
            "cs:~user/series/huh/name-1", "invalid form")
        self.assert_cannot_parse(
            "local:~user/series/name", "users not allowed in local URLs")
        self.assert_cannot_parse(
            "local:~user/name", "users not allowed in local URLs")
        self.assert_cannot_parse(
            "local:name", "invalid form")


class EndpointSolverTest(Base):

    def setUp(self):
        self.repo_dir = self.mkdir()
        self.repo = CharmRepository(self.repo_dir)

        class EnvAdapter(object):
            def env_get_service(self, name):
                return Service({
                    'name': name, 'charm_url': 'local:trusty/%s' % name})
        self.solver = EndpointSolver(EnvAdapter(), self.repo)

        self.write_local_charm({
            'name': 'db',
            'series': 'trusty',
            'peers': {
                'cluster': {
                    'interface': 'reprap'}},
            'provides': {
                'db': {
                    'interface': 'mysql'}}})
        self.write_local_charm({
            'name': 'wiki',
            'series': 'trusty',
            'requires': {
                'db-write': {
                    'interface': 'mysql'},
                'db-read': {
                    'interface': 'mysql'}}})
        self.write_local_charm({
            'name': 'blog',
            'series': 'trusty',
            'peers': {
                'cluster': {
                    'scope': 'global',
                    'interface': 'reprap'}},
            'requires': {
                'backend': {
                    'interface': 'mysql'}}})
        self.write_local_charm({
            'name': 'metrics',
            'series': 'trusty',
            'subordinate': True,
            'requires': {
                'backend': {
                    'interface': 'mysql',
                    'scope': 'container'}}})

    def test_match_provide_require(self):
        db, blog, pairs = self.solver.solve('db', 'blog')
        self.assertEqual(pairs, [(
            {'interface': 'mysql', 'name': u'db', 'scope': 'global',
             'role': u'provider', 'service': 'db', 'limit': 0,
             'optional': False},
            {'interface': 'mysql', 'name': u'backend', 'scope': 'global',
             'role': u'requirer', 'service': 'blog', 'limit': 1,
             'optional': False},
            'global')])

    def test_match_ambigious_provide_require(self):
        db, wiki, pairs = self.solver.solve('db', 'wiki')
        self.assertEqual(pairs, [
            ({'interface': 'mysql', 'name': 'db', 'scope': 'global',
              'role': 'provider', 'service': 'db', 'limit': 0,
              'optional': False},
             {'interface': 'mysql', 'name': 'db-read', 'scope': 'global',
              'role': 'requirer', 'service': 'wiki', 'limit': 1,
              'optional': False},
             'global'),
            ({'interface': 'mysql', 'name': 'db', 'scope': 'global',
              'role': 'provider', 'service': 'db', 'limit': 0,
              'optional': False},
             {'interface': 'mysql', 'name': 'db-write', 'scope': 'global',
              'role': 'requirer', 'service': 'wiki', 'limit': 1,
              'optional': False},
             'global')])

    def test_rel_container_scope(self):
        db, wiki, pairs = self.solver.solve('db', 'metrics')
        self.assertEqual(pairs, [
            ({'interface': 'mysql', 'name': 'db', 'scope': 'global',
              'role': 'provider', 'service': 'db', 'limit': 0,
              'optional': False},
             {'interface': 'mysql', 'name': 'backend', 'scope': 'container',
              'role': 'requirer', 'service': 'metrics', 'limit': 1,
              'optional': False},
             'container')])

    def test_rel_name_specified(self):
        db, wiki, pairs = self.solver.solve('db:db', 'wiki:db-read')
        self.assertEqual(pairs, [
            ({'interface': 'mysql', 'name': 'db', 'scope': 'global',
              'role': 'provider', 'service': 'db', 'limit': 0,
              'optional': False},
             {'interface': 'mysql', 'name': 'db-read', 'scope': 'global',
              'role': 'requirer', 'service': 'wiki', 'limit': 1,
              'optional': False},
             'global')])

    def test_rel_name_partial(self):
        db, wiki, pairs = self.solver.solve('db', 'wiki:db-read')
        self.assertEqual(pairs, [
            ({'interface': 'mysql', 'name': 'db', 'scope': 'global',
              'role': 'provider', 'service': 'db', 'limit': 0,
              'optional': False},
             {'interface': 'mysql', 'name': 'db-read', 'scope': 'global',
              'role': 'requirer', 'service': 'wiki', 'limit': 1,
              'optional': False},
             'global')])

    def test_match_peer(self):
        db, db, pairs = self.solver.solve('db', 'db')
        self.assertEqual(pairs, [
            ({'interface': 'reprap', 'name': 'cluster', 'limit': 1,
              'role': 'peer', 'service': 'db', 'scope': 'global',
              'optional': False},
             {'interface': 'reprap', 'name': 'cluster', 'limit': 1,
              'role': 'peer', 'service': 'db', 'scope': 'global',
              'optional': False},
             'global')])

    def test_no_match(self):
        self.write_local_charm({
            'name': 'mouse',
            'series': 'trusty'})
        db, mouse, pairs = self.solver.solve('db', 'mouse')
        self.assertEqual(pairs, [])


class CharmTest(Base):
    def setUp(self):
        self.repo_dir = self.mkdir()
        self.repo = CharmRepository(self.repo_dir)
        self.write_local_charm({
            'name': 'magic',
            'series': 'trusty',
            'peers': {
                'cluster': {
                    'scope': 'global',
                    'interface': 'reprap'}},
            'requires': {
                'storage': {
                    'interface': 'shared-fs'}},
            'provides': {
                'db': {
                    'scope': 'global',
                    'interface': 'mysql'}}}, {
            'options': {
                'debug-level': {
                    'type': 'boolean',
                    'default': False}}})

    def test_local_charm_increments(self):
        charm = self.repo.get('local:trusty/magic')
        self.assertEqual(charm.charm_url, 'local:trusty/magic-0')
        charm = self.repo.get('local:trusty/magic')
        self.assertEqual(charm.charm_url, 'local:trusty/magic-1')

    def test_charm_get_defaults(self):
        charm = self.repo.get('local:trusty/magic')
        self.assertEqual(charm.get_defaults(), {'debug-level': False})

    def test_charm_endpoints(self):
        charm = self.repo.get('local:trusty/magic')
        self.assertEqual(charm.endpoints, [
            {'interface': 'mysql', 'name': 'db', 'limit': 0,
             'role': 'provider', 'scope': 'global', 'optional': False},
            {'interface': 'shared-fs', 'name': 'storage', 'limit': 1,
             'role': 'requirer', 'scope': 'global', 'optional': False},
            {'interface': 'reprap', 'name': 'cluster', 'limit': 1,
             'role': 'peer', 'scope': 'global', 'optional': False},
            {'interface': 'juju-info', 'name': 'juju-info', 'limit': 0,
             'role': 'provider', 'scope': 'global', 'optional': True}])

    def test_charm_format(self):
        charm = self.repo.get('local:trusty/magic')
        self.assertEqual(charm.format_api(), {

            'Config': {'Options': {'debug-level': {
                'default': False, 'type': 'boolean'}}},
            'Format': 1,
            'Meta': {'Name': 'magic',
                     'Series': 'trusty',
                     'Peers': {'cluster': {
                         'interface': 'reprap', 'scope': 'global'}},
                     'Provides': {'db': {
                         'interface': 'mysql', 'scope': 'global'}},
                     'Requires': {'storage': {'interface': 'shared-fs'}}},
            'Revision': 0,
            'URL': 'local:trusty/magic-0'})


class CharmRepoTest(Base):

    def setUp(self):
        self.repo_dir = self.mkdir()
        self.repo = CharmRepository(self.repo_dir)

    @unittest.skipIf(TEST_OFFLINE, "Requires network access to charm store")
    def test_add_charm(self):
        self.repo.add_charm('cs:precise/mysql')
        data = self.repo.get('cs:precise/mysql')
        self.assertTrue(
            'query-cache-size' in data['config']['options'].keys())
        self.assertTrue(
            'shared-db' in data['metadata']['provides'].keys())

    @unittest.skipIf(TEST_OFFLINE, "Requires network access to charm store")
    def test_add_unknown_charm(self):
        self.assertRaises(
            CharmURLError, self.repo.add_charm, 'cs:precise/mysql12')


class ConstraintTest(Base):

    def test_actualize(self):
        x = Constraints.actualize(
            {'mem': 2000, 'cpu-cores': 4, 'root-disk': 8192})
        self.assertEqual(x.cpu_cores, 4)
        self.assertEqual(x.mem, 2000)
        self.assertRaises(
            ConstraintError, Constraints.actualize, {'mem': '8G'})

    def test_satisifes(self):
        x = Constraints.actualize({'mem': 8000, 'cpu-cores': 4})
        y = Constraints.actualize({'mem': 4000, 'cpu-cores': 2})

        self.assertEqual(x.format(), "cpu-cores=4 mem=8000")
        self.assertEqual(
            x.serialize(), {'mem': 8000, 'cpu-cores': 4})
        self.assertTrue(y.satisfied_by(x))
        self.assertFalse(x.satisfied_by(y))

        x = Constraints.actualize({'tags': ['super', 'special']})
        y = Constraints.actualize({'tags': ['super']})

        self.assertTrue(y.satisfied_by(x))
        self.assertFalse(x.satisfied_by(y))


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


if __name__ == '__main__':
    import unittest
    unittest.main()
