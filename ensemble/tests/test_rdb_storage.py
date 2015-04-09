
from sqlalchemy import select
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from base import Base as TestBase

from ..core.constraint import Constraints
from ..storage.rdb import (
    Base, Environment, Charm, Machine, RDBStorage,
    Service, Relation)
# Service, Unit, Relation


class TestRDBStorage(TestBase):

    def setUp(self):
        self.engine = create_engine('sqlite:///:memory:', echo=False)

        Base.metadata.create_all(self.engine)

        self._sfactory = sessionmaker(bind=self.engine)
        self.s = lambda: self._sfactory()

        s = self.s()
        self.e = Environment(name='abc', uid='xyz', namespace='/nxt')
        s.add(self.e)
        s.commit()
        s.refresh(self.e)

    def _t(self, c):
        return c.__table__

    def _q(self, *args, **kw):
        return self.engine.execute(select(*args, **kw))

    def assertQuery(self, query, values):
        if issubclass(query, Base):
            query = select([self._t(query)])
        results = self.engine.execute(query)
        self.assertEqual(results.fetchall(), values)

    def test_db_env_basic(self):
        s = self.s()
        e = Environment(name='zebra', uid='uuid', namespace='/xyz')
        c = Charm(url='cs:trusty/mysql', env=e)
        s.add(e)
        s.add(c)
        s.commit()

        self.assertQuery(
            Environment,
            [(1, u'abc', u'xyz', u'/nxt'),
             (2, u'zebra', u'uuid', u'/xyz')])

        self.assertEqual(e.charms, [c])

    def test_storage_add_unit(self):
        s = self.s()
        c = Charm(url='cs:trusty/something',
                  environment_id=self.e.id)
        svc = Service(name='client', charm=c,
                      environment_id=self.e.id)
        m = Machine(mid='0', state='pending',
                    environment_id=self.e.id)
        map(s.add, [c, m, svc])
        s.flush()
        rs = RDBStorage(s, 1)
        u = rs.add_unit(svc, m)
        self.assertEqual(u.name, 'client/0')

    def test_storage_add_machine(self):
        s = self.s()
        rs = RDBStorage(s, 1)
        m = rs.add_machine({
            'agent_version': '12.1.0',
            'mid': '1',
            'series': 'trusty',
            'state': 'started',
            # TODO networks as mapping of subnet to array of ip addresses.
            'public_address': '10.0.2.1',
            'private_address': '192.168.1.1',
            'constraints': Constraints.actualize({'mem': 2000}),
            'instance_id': u"i-xza",
            'instance_state': 'running'})
        self.assertEqual(m.mid, '1')
        rs.commit()
        self.assertEqual(rs.machine('1').instance_id, 'i-xza')

    def test_storage_machines(self):
        s = self.s()
        e = Environment(name='zebra', uid='uuid', namespace='/xyz')
        m = Machine(mid='0', env=e, state='pending')
        s.add(e)
        s.add(m)
        s.commit()
        s.refresh(m)
        s.close()

        s = self.s()
        rs = RDBStorage(s, 2)
        self.assertEqual(
            [x.mid for x in rs.machines()],
            [m.mid])

        self.assertEqual(rs.machine('0').mid, '0')
        self.assertEqual(rs.machine('4'), None)

    def test_storage_service_relations(self):
        s = self.s()

        e = Environment(name='zebra', uid='uuid', namespace='/xyz')
        c = Charm(url='cs:trusty/something', env=e)
        s1 = Service(name='client', charm=c, env=e)
        s2 = Service(name='server', charm=c, env=e)
        r = Relation(source=s2, target=s1, source_name='db',
                     target_name='client', env=e)
        map(s.add, [e, c, s1, s2, r])
        s.commit()

        rs = RDBStorage(s, 2)
        self.assertEqual(
            sorted([x.name for x in rs.services()]),
            ['client', 'server'])

        self.assertEqual(
            [(x.source_name, x.target_name) for x in rs.relations()],
            [('db', 'client')])

        self.assertEqual(rs.service('server').charm.url, 'cs:trusty/something')
