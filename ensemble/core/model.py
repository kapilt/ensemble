
import collections
import random

from errors import EnvError
from utils import normalize


class Lifecycle(object):

    started = u'started'
    stopped = u'stopped'
    running = u'running'
    error = u'error'

    alive = u'alive'
    dying = u'dying'
    dead = u'dead'

    changed = u'change'
    removed = u'removed'


CONTAINER_TYPES = (u'lxc', u'kvm')

Event = collections.namedtuple(
    'Event', ['type', 'change', 'entity_id', 'data'])


class ItemGetter(object):
    __slots__ = ('key', 'default')

    def __init__(self, key, default=None):
        self.key = key
        self.default = default

    def __call__(self, obj):
        try:
            return obj[self.key]
        except KeyError:
            return self.default


class ResourceType(type):

    def __new__(cls, name, parents, dict):
        if '_attrs' in dict:
            for attr in dict['_attrs']:
                if isinstance(attr, tuple):
                    attr, default = attr
                else:
                    default = None
                dict[attr] = property(ItemGetter(attr, default))
        return super(ResourceType, cls).__new__(cls, name, parents, dict)


class Resource(dict):

    __slots__ = ()
    __metaclass__ = ResourceType


class Charm(Resource):

    _attrs = ('metadata', 'charm_url', 'config', 'name')

    def __init__(self, *args, **kw):
        super(Charm, self).__init__(*args, **kw)
        from charm import parse_charm_url
        self._url = parse_charm_url(self.charm_url)

    @property
    def subordinate(self):
        return self['metadata'].get('subordinate', False)

    @property
    def provides(self):
        return self['metadata'].get('provides', {}) or {}

    @property
    def requires(self):
        return self['metadata'].get('requires', {}) or {}

    @property
    def peers(self):
        return self['metadata'].get('peers', {}) or {}

    @property
    def endpoints(self):
        endpoints = []
        for collection, role in (
            ('provides', u'provider'),
            ('requires', u'requirer'),
                ('peers', u'peer')):
            collection = self['metadata'].get(collection, None)
            if collection is None:
                continue
            for name, ep in collection.items():
                endpoints.append({
                    'interface': ep['interface'],
                    'role': role,
                    'optional': False,
                    'limit': int(role != 'provider'),
                    'scope': ep.get('scope', 'global'),
                    'name': unicode(name)})
        if not self.subordinate:
            endpoints.append({'interface': 'juju-info',
                              'role': 'provider',
                              'scope': 'global',
                              'limit': 0,
                              'optional': True,
                              'name': 'juju-info'})
        return endpoints

    def format_api(self):
        data = {
            u'URL':  self.charm_url,
            u'Format': 1,
            u'Revision': self._url.revision,
            u'Meta': normalize(self.metadata, 'capitalize')}
        if self.config:
            data[u'Config'] = {u'Options': dict(self.config['options'])}
        return data

    def get_defaults(self):
        if not self.config:
            return {}
        d = {}
        for k, v in self.config['options'].items():
            d[k] = v['default']
        return d

    def validate(self, data):
        """ validate config against data."""

        for k, v in data.items():
            if k not in self.config:
                raise EnvError({'Error': 'Invalid config key %s' % k})


class Unit(Resource):

    __slots__ = ('subordinates',)

    _attrs = ('state', 'agent_version', 'id',
              'private_address', 'public_address', 'machine',
              ('life', u''), ('charm', u''))

    def __init__(self, *args, **kw):
        super(Unit, self).__init__(*args, **kw)
        self.subordinates = {}

    def add_sub(self, sub_unit):
        self.subordinates[sub_unit.id] = sub_unit

    def remove_subs(self, sub_svc):
        sub_units = [sid for sid in self.subordinates
                     if sid.startswith(sub_svc.name)]

        removed = []
        for sub_id in sub_units:
            removed.append(self.subordinates.pop(sub_id))
            sub_svc.remove_unit(sub_id)
        return removed

    def format_status(self):
        subordinates = None
        if self.subordinates:
            subordinates = {}
            for s in self.subordinates.values():
                subordinates[s.id] = s.format_status()
        return {
            u'Agent': {u'Data': {},
                       u'Err': None,
                       u'Info': u'',
                       u'Life': u'',
                       u'Status': self.state,
                       u'Version': self.agent_version},
            u'AgentState': self.state,
            u'AgentStateInfo': u'',
            u'AgentVersion': self.agent_version,
            u'Charm': u'',
            u'Err': None,
            u'Life': u'',
            u'Machine': self.machine,
            u'OpenedPorts': [],
            u'PublicAddress': self.public_address.value,
            u'Subordinates': subordinates}

    def format_event(self, change=Lifecycle.changed):
        return Event(
            'unit', change, self.id,
            {u'CharmURL': self['charm_url'],
             u'Name': self.id,
             u'Ports': [],
             u'MachineId': self['machine'],
             u'PrivateAddress': self['private_address'].value,
             u'PublicAddress': self['public_address'].value,
             u'Series': self['series'],
             u'Service': self['id'].split('/')[0],
             u'StatusData': None,
             u'StatusInfo': u''
             })


class Service(Resource):

    __slots__ = ('unit_sequence', 'units', 'relations', 'principal_svcs')
    _attrs = ('name', 'charm_url', 'config', 'constraints', ('exposed', False))

    def __init__(self, *args, **kw):
        super(Service, self).__init__(*args, **kw)
        self.unit_sequence = 0
        self.units = {}
        self.relations = {}
        self.principal_svcs = []

    @property
    def id(self):
        return self['name']

    @property
    def subordinate(self):
        return self['charm'].subordinate

    @property
    def series(self):
        from charm import parse_charm_url
        return parse_charm_url(self.charm_url).series

    def add_principal(self, p):
        self.principal_svcs.append(p)

    def add_unit(self, machine, state=Lifecycle.started):
        uid = u"%s/%s" % (self.name, self.unit_sequence)
        self.unit_sequence += 1
        self.units[uid] = u = Unit({
            'id': uid,
            'state': state,
            'machine': machine.id,
            'charm_url': self.charm_url,
            'series': self.series,
            'public_address': machine.public_address,
            'private_address': machine.private_address,
            'agent_version': machine.agent_version})
        return u

    def remove_unit(self, uid):
        if not uid in self.units:
            raise EnvError({
                "some units not destroyed: '%s' does not exist" % uid})
        del self.units[uid]

    def add_relation(self, local_name, remote_service):
        self.relations.setdefault(local_name, []).append(remote_service)

    def remove_relation(self, local_name, remote_service):
        self.relations[local_name].remove(remote_service)

    def format_status(self):
        units = None
        if not self.subordinate:
            units = dict([
                (unicode(uid), u.format_status())
                for uid, u in self.units.items()])

        return {
            #u'CanUpgradeTo': u'',
            u'Charm': self.charm_url,
            u'Err': None,
            u'Exposed': self.exposed,
            u'Life': u'',
            u'Networks': {u'Disabled': None, u'Enabled': None},
            u'Relations': self.relations,
            u'SubordinateTo': list(self.principal_svcs),
            u'Units': units}

    def format_event(self, change=Lifecycle.changed):
        constraints = self.get('constraints')
        if not constraints:
            constraints = {}
        else:
            constraints = constraints.serialize()

        return Event(
            'service', change, self.name,
            {u'CharmURL': self['charm_url'],
             u'Name': self['name'],
             u'Exposed': self.exposed,
             u'Life': Lifecycle.alive,
             u'MinUnits': len(self.units),
             u'Config': self.config or {},
             u'Constraints': constraints,
             u'OwnerTag': u'user-admin'
             })


class Relation(Resource):

    __slots__ = ()
    _attrs = (('scope', u'global'), 'interface', 'id', 'key', 'endpoints')

    def format_status(self):
        return {
            u'Endpoints': [dict(
                {u'Name': e['name'],
                 u'Role': e['role'],
                 u'Subordinate': False,  # TODO
                 u'ServiceName': e['service']})
                for e in self.endpoints],
            u'Id': self.id,
            u'Key': self.key,
            u'Interface': self.interface,
            u'Scope': self.scope}

    def format_event(self, change=Lifecycle.changed):
        return Event(
            'relation', change, self.id,
            {'Id': self.id,
             'Key': self.key,
             'Endpoints': [dict({
                 u'Name': e['name'],
                 u'Limit': e['limit'],
                 u'Role': e['role'],
                 u'Optional': e['optional'],
                 u'Scope': e['scope']}) for e in self.endpoints]})


class Machine(Resource):

    __slots__ = ('container_sequence', 'containers')
    _attrs = ('state', 'agent_version', 'instance_id', 'id', 'series',
              'public_address', 'private_address', 'constraints',
              'hardware', 'dnsname', 'instance_state', 'life', 'dirty')

    def __init__(self, *args, **kw):
        super(Machine, self).__init__(*args, **kw)
        self.container_sequence = dict([(ct, 0) for ct in CONTAINER_TYPES])
        self.containers = {}

    def add_container(self, container):
        self.containers[container.id] = container

    def exists(self, cid):
        return cid in self.containers

    def remove_container(self, container_id):
        return self.containers.pop(container_id)

    def format_event(self, change=Lifecycle.changed):
        return Event(
            u'machine', change, self.id, {
                u'Addresses': [a.format_event() for a in [
                    self.public_address, self.private_address]],
                u'HardwareCharacteristics': {
                    u'Arch': u'amd64',
                    u'CpuCores': 1,
                    u'CpuPower': 100,
                    u'Mem': 1740,
                    u'RootDisk': 8192},
                u'Series':  self.series,
                u'StatusData': None,
                u'StatusInfo': u'',
                u'Status': self.instance_state,
                u'Life': self.life,
                u'SupportedContainers': ['lxc'],
                u'SupportContainersKnown': True})

    def format_status(self):
        return {u'Agent': {u'Data': {},
                           u'Err': None,
                           u'Info': u'',
                           u'Life': u'',
                           u'Status': self.state,
                           u'Version': self.agent_version},
                u'AgentState': self.state,
                u'AgentStateInfo': u'',
                u'AgentVersion': self.agent_version,
                u'Containers': dict([
                    (k, v.format_status()) for
                    k, v in self.containers.items()]),
                u'DNSName': self.public_address.value,
                u'Err': None,
                #u'Hardware': u'arch=amd64 cpu-cores=2 mem=2001M',
                #u'HasVote': True,
                u'Id': self.id,
                u'InstanceId': self.instance_id,
                u'InstanceState': self.instance_state,
                u'Jobs': [u'JobHostUnits'],
                u'Life': u'',
                u'Series': self.series,
                #u'WantsVote': True}
                }


class Network(object):

    SCOPES = ('public', 'local-cloud')
    TYPES = ('ipv4', 'hostname')

    def __init__(self, satyr_ip, name, scope):
        self.satyr_ip = satyr_ip  # Like a cidr but not ;-) no bitmask, 0 = *
        self.name = name
        self.allocated_ipv4 = set()
        self.scope = scope

    def allocate_ipv4(self):
        ip = []
        parts = self.satyr_ip.split('.')
        while True:
            for p in parts:
                if p == '0':
                    ip.append(str(random.randrange(1, 255)))
                else:
                    ip.append(p)
            addr = ".".join(ip)
            if not addr in self.allocated_ipv4:
                self.allocated_ipv4.add(addr)
                return NetworkAddress(
                    self.name, self.scope, u'ipv4', addr)


class NetworkAddress(collections.namedtuple(
        'NetworkAddress', ['name', 'scope', 'type', 'value'])):

    def format_event(self):
        return {u'NetworkName': self.name,
                u'Scope': self.scope,
                u'Type': self.type,
                u'Value': self.value}
