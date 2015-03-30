from sqlalchemy import Column, Integer, String, ForeignKey, Sequence
from sqlalchemy.orm import relationship, backref
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.declarative import ConcreteBase

Base = declarative_base()


class Environment(Base):
    __tablename__ = 'environments'

    id = Column(Integer, Sequence('env_id_seq'), primary_key=True)
    name = Column(String)
    uid = Column(String)
    namespace = Column(String)


class Service(Base):
    __tablename__ = 'services'

    id = Column(Integer, Sequence('svc_id_seq'), primary_key=True)
    env_id = Column(Integer, ForeignKey('environments.id'))
    name = Column(String)
    charm_id = Column(Integer, ForeignKey('charms.id'))
    constraints = Column(String)

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
    service_id = Column(Integer, ForeignKey('services.id'))
    constraints = Column(String)
    machine_id = Column(Integer, ForeignKey('machines.id'))

    service = relationship('Service', backref=backref('units', order_by=id))
    machine = relationship('Machine', backref=backref('units', order_by=id))


class Charm(Base):
    __tablename__ = 'charms'

    id = Column(Integer, Sequence('charm_id_seq'), primary_key=True)
    env_id = Column(Integer, ForeignKey('environments.id'))
    url = Column(String)
    storage_uri = Column(String)
    storage_type = Column(String)

    env = relationship('Environment', backref=backref('charms', order_by=id))


class Relation(Base):
    __tablename__ = 'relations'

    id = Column(Integer, Sequence('rel_id_seq'), primary_key=True)
    env_id = Column(Integer, ForeignKey('environments.id'))
    name = Column(String)
    source_id = Column(Integer, ForeignKey('services.id'))
    source_name = Column(String)
    target_id = Column(Integer, ForeignKey('services.id'))
    target_name = Column(String)

    source = relationship('Service', foreign_keys=[source_id])
    target = relationship('Service', foreign_keys=[target_id])


class Machine(Base):
    __tablename__ = 'machines'

    id = Column(Integer, Sequence('machine_id_seq'), primary_key=True)
    mid = Column(String)
    constraints = Column(String)
    type = Column(String)


class MachinePool(ConcreteBase, Base):
    __tablename__ = 'machine_pools'

    id = Column(Integer, Sequence('machine_pool_id_seq'), primary_key=True)
    env_id = Column(Integer, ForeignKey('environments.id'))
    name = Column(String)
    type = Column(String)

    __mapper_args__ = {
        'polymorphic_identity': 'pool',
        'polymorphic_on': type}


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


def main():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    engine = create_engine('sqlite:///:memory:', echo=True)
    Base.metadata.create_all(engine)

    Session = sessionmaker(bind=engine)

    s = Session()
    e = Environment(name='zebra', uid='zebra', namespace='/xyz')
    c = Charm(url='cs:trusty/mysql', env=e)

    s.add(e)
    s.add(c)

    s.commit()


if __name__ == '__main__':
    main()
