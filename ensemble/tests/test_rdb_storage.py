
from sqlalchemy import select
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from base import Base as TestBase

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
            [(1, u'zebra', u'uuid', u'/xyz')])

        self.assertEqual(e.charms, [c])

    def test_storage_machines(self):
        s = self.s()
        e = Environment(name='zebra', uid='uuid', namespace='/xyz')
        m = Machine(mid='0', env=e, state='pending')
        s.add(e)
        s.add(m)
        s.commit()
        s.close()

        s = self.s()
        rs = RDBStorage(s, 1)
        self.assertEqual(
            rs.machines(),
            [m])

    def xtest_storage_service_relations(self):
        s = self.s()

        e = Environment(name='zebra', uid='uuid', namespace='/xyz')
        c = Charm(url='cs:trusty/something', env=e)
        s1 = Service(name='client', charm=c, env=e)
        s2 = Service(name='server', charm=c, env=e)
        r = Relation(source=s2, target=s1, source_name='db',
                     target_name='client', env=e)
        map(s.add, [e, c, s1, s2, r])
        s.commit()

        rs = RDBStorage(s, 1)
        self.assertEqual(
            rs.services(),
            None)
