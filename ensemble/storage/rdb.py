from sqlalchemy import (
    Column, Integer, String, ForeignKey, Sequence, Boolean, and_)
from sqlalchemy.orm import relationship, backref
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.declarative import ConcreteBase

from util import JSONType, ConstraintType

Base = declarative_base()


class RDBStorage(object):

    def __init__(self, session, env_id):
        self.session = session
        self.env_id = env_id

    def commit(self):
        self.session.commit()

    def abort(self):
        self.session.abort()

    def _store(self, o):
        self.session.add(o)
        self.session.flush()
        self.session.refresh(o)
        return o

    def machines(self):
        return list(self.session.query(Machine).filter(
            Machine.environment_id == self.env_id))

    def machine(self, mid):
        return self.session.query(Machine).filter(
            and_(Machine.environment_id == self.env_id,
                 Machine.mid == mid)).scalar()

    def services(self):
        return list(self.session.query(Service).filter(
            Service.environment_id == self.env_id))

    def service(self, name):
        return self.session.query(Service).filter(
            and_(Service.environment_id == self.env_id,
                 Service.name == name)).scalar()

    def relations(self):
        return list(self.session.query(Relation).filter(
            Relation.environment_id == self.env_id))

    def annotation(self, entity_type, entity_id, key):
        pass

    # mutators

    def add_machine(self, machine_data):
        machine_data['environment_id'] = self.env_id
        return self._store(Machine(**machine_data))

    def add_unit(self, svc, m):
        u = Unit(
            name="%s/%s" % (svc.name, svc.unit_sequence),
            machine=m,
            charm_url=svc.charm.url)
        svc.unit_sequence += 1
        return self._store(u)

    def add_service(self, service_data):
        s = Service(**service_data)
        return self._store(s)


class Environment(Base):
    __tablename__ = 'environments'

    id = Column(Integer, Sequence('env_id_seq'), primary_key=True)
    name = Column(String)
    uid = Column(String)
    namespace = Column(String)


class Service(Base):
    __tablename__ = 'services'

    id = Column(Integer, Sequence('svc_id_seq'), primary_key=True)
    environment_id = Column(Integer, ForeignKey('environments.id'))
    name = Column(String)
    charm_id = Column(Integer, ForeignKey('charms.id'))
    constraints = Column(String)
    unit_sequence = Column(Integer, default=0)
    subordinate = Column(Boolean)

    env = relationship("Environment", backref=backref('services', order_by=id))
    charm = relationship("Charm", backref=backref('services', order_by=id))
    relations = relationship(
        'Relation',
        primaryjoin="or_(Service.id==Relation.source_id,"
                    "Service.id==Relation.target_id)")


class Unit(Base):
    __tablename__ = 'units'

    id = Column(Integer, Sequence('unit_id_seq'), primary_key=True)

    name = Column(String)
    agent_version = Column(String)
    charm_url = Column(String)
    service_id = Column(Integer, ForeignKey('services.id'))
    constraints = Column(String)
    machine_id = Column(Integer, ForeignKey('machines.id'))

    # not a full tree, one level deep.
    parent_unit_id = Column(Integer, ForeignKey('units.id'))

    service = relationship('Service', backref=backref('units', order_by=id))
    machine = relationship('Machine', backref=backref('units', order_by=id))
    subordinates = relationship(
        'Unit', backref=backref('parent', order_by=id, remote_side=[id]))


class Charm(Base):
    __tablename__ = 'charms'

    id = Column(Integer, Sequence('charm_id_seq'), primary_key=True)
    environment_id = Column(Integer, ForeignKey('environments.id'))
    url = Column(String)
    storage_uri = Column(String)
    storage_type = Column(String)

    env = relationship('Environment', backref=backref('charms', order_by=id))


class Relation(Base):
    __tablename__ = 'relations'

    id = Column(Integer, Sequence('rel_id_seq'), primary_key=True)
    environment_id = Column(Integer, ForeignKey('environments.id'))

    name = Column(String)
    source_id = Column(Integer, ForeignKey('services.id'))
    source_name = Column(String)
    target_id = Column(Integer, ForeignKey('services.id'))
    target_name = Column(String)

    source = relationship('Service', foreign_keys=[source_id])
    target = relationship('Service', foreign_keys=[target_id])

    env = relationship(
        'Environment', backref=backref('relations', order_by=id))


class Machine(Base):
    __tablename__ = 'machines'

    _id = Column(Integer, Sequence('machine_id_seq'), primary_key=True)

    id = Column(String)
    environment_id = Column(Integer, ForeignKey('environments.id'))

    agent_version = Column(String)
    state = Column(String)

    constraints = Column(ConstraintType)
    series = Column(String)
    image_id = Column(String)

    container_seq = Column(Integer, default=0)
    container_type = Column(String)
    container_parent_id = Column(Integer, ForeignKey('machines.id'))

    private_address = Column(String)
    public_address = Column(String)

    instance_id = Column(String)
    instance_state = Column(String)
    instance_data = Column(JSONType)

    env = relationship("Environment", backref=backref('machines', order_by=id))

    # TODO add adjancey list for machine_units and child container units


class MachinePool(ConcreteBase, Base):
    __tablename__ = 'machine_pools'

    id = Column(Integer, Sequence('machine_pool_id_seq'), primary_key=True)
    env_id = Column(Integer, ForeignKey('environments.id'))
    name = Column(String)
    mtype = Column(String)

    __mapper_args__ = {
        'polymorphic_identity': 'pool',
        'polymorphic_on': mtype}


class AutoScaleGroup(MachinePool):

    __tablename__ = 'autoscale_groups'
    name = ""

    id = Column(Integer, Sequence('machine_pool_id_seq'), primary_key=True)
    min_size = Column(Integer)
    max_size = Column(Integer)
    launch_profile = Column(String)

    __mapper_args__ = {
        'polymorphic_identity': 'autoscale_group',
        'concrete': True}
