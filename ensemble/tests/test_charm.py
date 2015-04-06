import unittest
from base import Base, TEST_OFFLINE

from ..core.charm import (
    parse_charm_url, CharmURLError, CharmRepository)


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
