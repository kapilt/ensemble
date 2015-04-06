
from ..core.charm import CharmRepository
from ..core.model import Service
from ..core.endpoint import EndpointSolver

from base import Base


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
