# -*- coding: latin-1 -*-
# ensemble
#
# Copyright © Kapil Thangavelu
# Author: Kapil Thangavelu <kapil.foss@gmail.com>
#
# See COPYING file for details.
#

"""
An in-memory environment implementation that responds to a large
subset of the juju client api.

A primary goal is to provide a more effective testing backend
for other tools using python for api based applications.

Features

  - Supports containers, placement, subordinates, constraints,
    store and local charms, watches, upgrades, relations, status,
    config, etc.

TODO

 - separate out env config into mutable/read-only
 - unit test to test compatibility vs same ops on a real env.
 - add test for deploy with service config

TODO / API Compatibility (py jujuclient.py)

 - info
 - upgrade_environment
 - add_local_charm
 - add_charm
 - get_constraints
 - set_env_constraints
 - get_env_constraints
 - retry_provisioning
 - valid_relation_names
 - get_public_address

TODO / API Compatibilty core (also needs jujuclient.py impl)

 - get_private_address / accessible via watch
 - get_service_charm_url / covered by serviceget
 - environment_uuid / covered by info
 - share_environment
 - unshare_environment
 - unset_env_config
 - find_tools
 - abort_current_upgrade
 - run_on_all_machines
 - run
 - destroy_environment
 - resolve_charm
 - upload_tools
 - api_host_ports
 - ensure_availability
 - agent_version
 - debug_log

 Other api facades

 - actions
     - list_all
     - list_pending
     - list_completed
     - cancel
     - enqueue

 - backups
     - create
     - download
     - info
     - list
     - remove

 - keys
     - list_keys
     - delete_keys
     - add_keys
     - import_keys

 - users
     - add_user
     - disable_user
     - enseble_user
     - user_info
     - set_password

Maybe

 - annotations stored on model objects / (for auto-gc)
 - owner support on objects
 - bundle support in CharmSet
 - transactions (not in core yet..) but needed.
 - container constraints (per above)
 - subordinate removal (per above)

Clone Support

 - needs hw to constraints translation
 - download local charm
 - going to need a cache / location ~/.juju/sync-cache

 - {'src': '', 'src-uuid': ''}
 - machine {'src-uuid': '', 'src-mid': '0'}
"""
import collections
import contextlib
import json
import os
import pprint
import random
import StringIO
import tempfile
import urllib2

import yaml

try:
    from jujuclient import EnvError
except ImportError:
    class EnvError(Exception):

        def __init__(self, error):
            super(EnvError, self).__init__(error)
            self.error = error
            self.message = error['Error']

        def __str__(self):
            stream = StringIO.StringIO()
            pprint.pprint(self.error, stream, indent=4)
            return "<Env Error - Details:\n %s >" % (
                stream.getvalue())

try:
    from yaml import CSafeLoader, CSafeDumper
    SafeLoader, SafeDumper = CSafeLoader, CSafeDumper
except ImportError:
    from yaml import SafeLoader


# Utility functions
def yaml_dump(value):
    return yaml.dump(value, default_flow_style=False)


def yaml_load(value):
    return yaml.load(value, Loader=SafeLoader)


# We're not using safe dumper because we're using other custom
# representers as well.
def _unicode_representer(dumper, uni):
    node = yaml.ScalarNode(tag=u'tag:yaml.org,2002:str', value=uni)
    return node

yaml.add_representer(unicode, _unicode_representer)


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
        self.satyr_ip = satyr_ip  # Like a cidr but not ;-) no bitmask
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


ENV_CONFIG_DEFAULT = {
    u'admin-secret': u'',
    u'agent-version': u'1.20.14',
    u'api-port': 17070,
    #u'authorized-keys': '',
    u'bootstrap-addresses-delay': 10,
    u'bootstrap-host': u'104.236.98.204',
    u'bootstrap-retry-delay': 5,
    u'bootstrap-timeout': 600,
    u'bootstrap-user': u'root',
    u'ca-cert': u'',
    u'ca-private-key': u'',
    u'charm-store-auth': u'',
    u'default-series': u'',
    u'development': True,
    u'disable-network-management': False,
    u'firewall-mode': u'instance',
    u'image-metadata-url': u'',
    u'image-stream': u'',
    u'logging-config': u'<root>=DEBUG;unit=DEBUG',
    u'lxc-clone-aufs': False,
    u'name': u'ocean',
    u'proxy-ssh': True,
    #u'rsyslog-ca-cert': u'',
    u'ssl-hostname-verification': True,
    u'state-port': 37017,
    u'storage-auth-key': u'a831e510-118a-41c5-801a-cab940397a20',
    u'storage-listen-ip': u'',
    u'storage-port': 8040,
    u'syslog-port': 6514,
    u'test-mode': False,
    #u'tools-metadata-url': u'',
    #u'tools-url': u'https://streams.canonical.com/juju/devel/tools',
    u'type': u'ensemble',
    u'use-sshstorage': False}


class Sync(object):
    """ NOTE: Sync is Not Complete
    TODO:
       - Capturing co-located placement
       - Options for removing
    """
    def __init__(self, src, tgt, options=None, handler=None):
        self.src = src
        self.tgt = tgt
        self.handler = handler or DeltaApplyHandler(tgt)
        self.options = options or {}

    def run(self):
        # Copy into mem environments to avoid extraneous rpcs
        src_mem, tgt_mem = Environment(), Environment()
        DeltaApplyHandler(src_mem)(event_stream(self.src))
        DeltaApplyHandler(tgt_mem)(event_stream(self.tgt))

        stream = DeltaStream()
        stream.consume(self._diff_services(src_mem, tgt_mem))
        stream.consume(self._diff_relations(src_mem, tgt_mem))
        stream.consume(self._diff_environment(src_mem, tgt_mem))
        self.handler(stream)

    def _diff_services(self, src, tgt):
        stream = DeltaStream()
        src_svcs = set(src.status()['Services'])
        tgt_svcs = set(tgt.status()['Services'])

        missing = src_svcs - tgt_svcs
        if missing:
            stream.add(Event('service'))

    def _diff_relations(self, src, tgt):
        pass

    def _diff_environment(self, src, tgt):
        pass


def clone(env):
    # TODO
    clone = Environment()
    handler = DeltaApplyHandler(clone)
    handler(event_stream(env))
    return clone


def event_stream(env):
    """First pump on any event stream captures current state."""
    w = env.get_watch()
    w.start()
    with w:
        return iter(w).next()


class DeltaApplyHandler(object):

    def __init__(self, env):
        self.env = env
        self.status = None

    def __call__(self, changes):
        for c in changes:
            self.dispatch(c)

    def dispatch(self, change):
        if self.status is None:
            self.status = self.env.status()

        change.insert(2, None)
        change = Event(*change)
        key = "handle_%s_%s" % (change.type, change.change)
        method = getattr(self, key, None)

        if not method:
            raise ValueError("No handler for %s" % key)

        method(change)

    def handle_machine_change(self, change):
        data = change.data['HardwareCharacteristics']
        #TODO for sync handler/ when we support placement

    def handle_service_change(self, change):
        svc_name = change.data['Name']
        if not svc_name in self.status['Services']:
            self.env.deploy(
                svc_name, change.data['CharmURL'])
        else:
            self.env.update_service(change.data)

    def handle_service_removed(self, change):
        self.env.destroy_service(change)

    def handle_unit_change(self, changed):
        u_name = changed.data['Name']
        svc_name = u_name.split('/')[0]
        units = self.status['Services'].get(svc_name, {}).get('Units', [])
        if u_name not in units:
            self.env.add_unit(svc_name)

    def handle_unit_removed(self, changed):
        self.env.remote_units([changed.data['Name']])

    def handle_relation_changed(self, changed):
        self.env.add_relation(changed['Endpoints'])

    def handle_annotation_changed(self, changed):
        key = changed.data['Tag']
        type, entity_id = key.split('-', 1)
        self.env.add_annotation(type, entity_id, changed.data['Annotations'])


class DeltaStream(object):
    """The minimal set of events to represent the current environment state.
    """
    def __init__(self):
        self._events = []
        self.previous = {}

    def __iter__(self):
        return iter(self._events)

    def clear(self):
        self._events = []

    def consume(self, events):
        for e in events:
            self.add(e)
        return self

    def add(self, evt):
        found, found_idx = None, None
        for i, e in enumerate(self._events):
            if e.entity_id == evt.entity_id:
                found_idx = i
                found = e
                break
        if evt.change != Lifecycle.removed:
            self._events.append(evt)
        if found is None:
            self.previous[evt.entity_id] = None
            return
        if found.change in (Lifecycle.removed, Lifecycle.changed):
            p = self._events.pop(found_idx)
            self.previous[p.entity_id] = Event(
                p.type, p.change, p.entity_id, dict(p.data))

        if evt.type == 'annotation':
            found.data.update(evt.data)
            evt.data.clear()
            evt.data.update(found.data)


class WatchManager(object):

    def __init__(self):
        self.stream = DeltaStream()
        self.watches = {}
        self.watch_sequence = 0

    def notify(self, evt):
        self.stream.add(evt)
        for w in self.watches.values():
            w._notify(evt)

    def watch(self):
        wid = self.watch_sequence
        self.watch_sequence += 1
        self.watches[wid] = w = Watch(self, wid)
        return w


class Watch(object):
    """Approximation of a watch, since operations against in mem are
    instaneous, goal state should immediately appear in a watch.

    It does not serve as a continous watch, and must be periodically
    polled (via next). The entire mock api is intended for usage from
    single threaded contexts for a which blocking watch doesn't make
    sense.
    """
    def __init__(self, mgr, wid):
        self.mgr = mgr
        self.wid = wid
        self.running = False
        self.pending = None

    def noop(self):
        pass

    start = reconnect = noop

    def stop(self):
        if self.wid in self.mgr.watches:
            del self.mgr.watches[self.wid]

    def _notify(self, evt):
        if not self.running:
            return
        self.pending.append(evt)

    def next(self):
        if self.running is False:
            changes = list(self.mgr.stream)
            self.running = True
            self.pending = []
            return [[c.type, c.change, c.data] for c in changes]
        elif self.running is None:
            return EnvError({"Error": "Can't watch on closed watcher"})
        if self.pending:
            changes = self.pending[:]
            self.pending = []
            return [[c.type, c.change, c.data] for c in changes]

        raise StopIteration()

    def __iter__(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, exc, v, t):
        self.stop()


class Environment(object):

    # TODO move state/db to separate abstraction.

    def __init__(self, env_name="", charms=None, charm_dir=None):
        self._annotations = {}
        self._config = {}
        self._machines = {}
        self._machine_sequence = 0
        self._relations = []
        self._relation_sequence = 0
        self._services = {}
        #self._watches = []
        self._auto_cleanup_charms = False
        if not charms or charm_dir:
            self._auto_cleanup_charms = True
            self._charm_dir = tempfile.mkdtemp()
        self._charms = charms or CharmRepository(charm_dir)
        self._env_version = u'1.20.14'
        self._networks = {
            u'public': Network('172.10.0.0', u'', 'public'),
            u'private': Network('192.168.0.0', u'', 'private')}
        # at the moment just needs env_get_service
        self._endpoints = EndpointSolver(self, self._charms)
        self._watches = WatchManager()

    @classmethod
    def connect(cls, *args, **kw):
        return cls(*args, **kw)

    def close(self):
        if self._auto_cleanup_charms:
            # _charm_dir variable won't even exist / attributeerror
            shutil.rmtree(self._charm_dir)

    def status(self, filters=None):
        # TODO filtering
        s = {}
        s['Machines'] = machines = {}
        for mid, m in self._machines.items():
            machines[mid] = m.format_status()

        s['Services'] = services = {}
        for sid, svc in self._services.items():
            services[sid] = svc.format_status()

        s['Relations'] = relations = []
        for r in self._relations:
            relations.append(r.format_status())

        s['Networks'] = {}
        return s

    def get_watch(self):
        return self._watches.watch()

    def get_charm(self, charm_url):
        return self._charms.get(charm_url)

    def get_env_config(self):
        d = dict(ENV_CONFIG_DEFAULT)
        d.update(self._config.get('juju.env', {}))
        return {u'Config': d}

    def set_env_config(self, mapping):
        self._config['juju-env'].update(mapping)

    def add_machine(self, series, constraints=None, machine_spec=None):
        if machine_spec is None:
            machine_id = unicode(self._machine_sequence)
            self._machine_sequence += 1
            m = Machine({
                'id': machine_id,
                'agent_version': self._env_version,
                'series': series,
                'state': Lifecycle.started,
                'public_address': self._networks['public'].allocate_ipv4(),
                'private_address': self._networks['private'].allocate_ipv4(),
                'constraints': Constraints.actualize(constraints),
                'instance_id': u"i-%s" % machine_id,
                'instance_state': Lifecycle.running})
            self._machines[machine_id] = m
            self._watches.notify(m.format_event())
            return {u'Machine': m.id, u'Error': None}

        p = self._validate_placement(self._parse_machine_spec(machine_spec))

        if p.container_type is None:
            raise EnvError({
                'Error': '''
                Container must be specified when adding a machine to another
                machine'''.strip()})

        if p.machine is None:
            r = self.add_machine(series, constraints)
            m = self._machines.get(r['Machine'])
        else:
            m = self.env_resolve_machine(p.machine)
        c = self._add_container(m, series, constraints, p.container_type)
        self._watches.notify(c.format_event())
        return {u'Machine': c.id, u'Error': None}

    def _add_container(self, machine, series, constraints, container_type):
        machine_id = u"%s/%s/%s" % (
            machine.id, container_type,
            machine.container_sequence[container_type])

        # Note core currently ignores constraints on containers.
        m = Machine({
            'id': machine_id,
            'agent_version': self._env_version,
            'series': series,
            'state': Lifecycle.started,
            'public_address': self._networks['public'].allocate_ipv4(),
            'private_address': self._networks['private'].allocate_ipv4(),
            'constraints': Constraints.actualize(constraints),
            'instance_id': u"i-%s" % machine_id,
            'instance_state': Lifecycle.running})
        machine.add_container(m)
        return m

    def _parse_machine_spec(self, machine_spec):
        machine = container_type = placement_type = value = None

        # Core only implements zone placement with this syntax atm.
        if '=' in machine_spec:
            placement_type, value = machine_spec.split("=", 1)

        # Create container placement
        elif ':' in machine_spec:
            container_type, machine = machine_spec.split(':', 1)

        # Create new machine & container placement
        elif machine_spec in CONTAINER_TYPES:
            container_type = machine_spec

        # Target existing machine or container
        else:
            machine = machine_spec

        return Placement(
            machine_spec, container_type, machine, placement_type, value)

    def _validate_placement(self, p):
        if p.placement_type:
            raise EnvError(
                {'Error': 'Non machine placement not supported %r' % (
                    p.machine_spec)})
        elif not p.machine:
            raise EnvError(
                {'Error': 'Unknown placement %r' % p.machine_spec})
        elif p.container_type and not p.container_type in CONTAINER_TYPES:
            raise EnvError(
                {'Error': 'Unknown container type %s' % p.machine_spec})
        return p

    def destroy_machines(self, machine_ids, force=False):
        for m in machine_ids:
            units = self._get_machine_units(m, children=True)
            if units:
                if not force:
                    raise EnvError({'Error': 'Machine %s has units %s' % (
                        m, ', '.join(units))})
                self.remove_units(units)
            if '/' in m:
                p = self.env_resolve_machine(m, parent=True)
                if not p.exists(m):
                    continue
                self._watches.notify(
                    p.remove_container(m).format_event('removed'))
            elif m in self._machines:
                self._watches.notify(
                    self._machines.pop(m).format_event('removed'))
        return {}

    def _get_machine_units(self, mid, children=False):
        res = []
        if children:
            children = '%s/' % mid
        for s in self._services.values():
            for u in s.units.values():
                if u.machine == mid:
                    res.append(u.id)
                if children:
                    if u.machine.startswith(children):
                        res.append(u.id)
        return res

    def add_relation(self, endpoint_a, endpoint_b):
        svc_a, svc_b, pairs = self._endpoints.solve(endpoint_a, endpoint_b)
        ep_a, ep_b, scope = self._validate_pairs(endpoint_a, endpoint_b, pairs)
        if ep_a['role'] == 'peer':
            key = "%s:%s" % (svc_a.name, ep_a['name'])
            pair = [ep_a]
        else:
            pair = [ep_a, ep_b]
            key = self._key_from_pair(pair)

        if self._find_rel(key):
            raise EnvError({"Error": "relation already exists '%s'" % key})

        r = Relation(
            {'key': key, 'id': self._relation_sequence,
             'endpoints': pair, 'scope': scope,
             'interface': ep_a['interface']})
        self._relation_sequence += 1
        self._relations.append(r)
        svc_a.add_relation(ep_a['name'], svc_b.name)
        if ep_a['role'] != 'peer':
            svc_b.add_relation(ep_b['name'], svc_a.name)

        self._watches.notify(r.format_event())
        if svc_a.subordinate or svc_b.subordinate:
            self._sync_subordinates(svc_a, svc_b)
        return {u'Endpoints': self._format_relation_result(pair)}

    def _format_relation_result(self, pair):
        d = {}
        for e in pair:
            d[e['service']] = {
                u'Name': e['name'],
                u'Scope': e['scope'],
                u'Interface': e['interface'],
                u'Role': e['role'],
                u'Limit': None,
                u'Optional': False}
        return d

    def _sync_subordinates(self, svc_a, svc_b, remove=False):
        primary = (not svc_a.subordinate and svc_a or svc_b)
        sub = (svc_a.subordinate and svc_a or svc_b)

        if remove:
            sub.remove_principal(primary.id)
        else:
            sub.add_principal(primary.id)

        for u in primary.units.values():
            self._sync_sub_unit(u, sub, remove)

    def _sync_sub_unit(self, u, sub, remove):
        u_sub_svcs = [n.split('/', 1)[0] for n in u.subordinates]
        if sub.id in u_sub_svcs:
            if remove:
                subs = u.remove_subs(sub)
                for s in subs:
                    self._watches.notify(s.format_event('remove'))
            return
        s_uid = self._add_unit(
            sub.name, machine_spec=u.machine,
            _subadd=True)['Units'].pop()
        s = sub.units[s_uid]
        # in memory ref, need to have status with context access
        u.add_sub(s)
        self._watches.notify(s.format_event())

    def _validate_pairs(self, endpoint_a, endpoint_b, pairs):
        if len(pairs) == 0:
            raise EnvError(
                {'Error': 'No possible relationship between %s and %s' % (
                    endpoint_a, endpoint_b)})
        elif len(pairs) > 1:
            raise EnvError(
                {'Error': 'Multiple possible relations between %s and %s' % (
                    endpoint_a, endpoint_b)})
        return pairs[0]

    def _key_from_pair(self, pair):
        # not entirely clear if key is needed..
        kp = [(pair[0]['service'], pair[0]['name']),
              (pair[1]['service'], pair[1]['name'])]
        kp.sort()
        key = u"%s:%s %s:%s" % (kp[0][0], kp[0][1], kp[1][0], kp[1][1])
        return key

    def _find_rel(self, key):
        found = False
        for r in self._relations:
            if r.key == key:
                if found is False:
                    found = r
                    break
        return found or None

    def remove_relation(self, endpoint_a, endpoint_b):
        svc_a, svc_b, pairs = self._endpoints.solve(endpoint_a, endpoint_b)
        pair = self._validate_pairs(endpoint_a, endpoint_b, pairs)
        key = self._key_from_pair(pair)
        r = self._find_rel(key)
        if r is None:
            raise EnvError({"Error": "relation does not exist '%s'" % key})
        svc_a.remove_relation(pair[0]['name'], svc_b.name)
        svc_b.remove_relation(pair[1]['name'], svc_a.name)
        self._relations.remove(r)
        self._watches.notify(r.format_event('removed'))

    def deploy(self, service_name, charm_url,
               num_units=1, config=None, constraints=None, machine_spec=None):
        charm = self._charms.get(charm_url)
        if not charm:
            raise EnvError({'Error': 'charm not found %s' % charm_url})
        if config:
            if not charm.validate(config):
                raise EnvError({'Error': 'invalid charm configuration'})
#        if machine_spec and not machine_spec in self._machines:
#            raise EnvError({'Error': 'machine %s not found' % machine_spec})
        s = Service({
            'name': unicode(service_name),
            'subordinate': charm.subordinate,
            'charm_url': charm.charm_url,
            'charm': charm,
            'config': config,
            'constraints': Constraints.actualize(constraints),
            'machine_spec': machine_spec})
        self._services[s.name] = s
        self._watches.notify(s.format_event())

        for p in charm.peers:
            self.add_relation(
                "%s:%s" % (service_name, p), "%s:%s" % (service_name, p))
        if not s.subordinate:
            self.add_unit(s.name, machine_spec)
        return {}

    def update_service(self, service_name, charm_url="", force_charm_url=False,
                       min_units=None, settings=None, constraints=None):
        """
        """
        if charm_url:
            self.set_charm_url(service_name, charm_url, force=force_charm_url)

        if settings:
            self.set_config(service_name, settings)

        if constraints:
            self.set_constraints(service_name, constraints)

        if min_units:
            svc = self.env_get_service(service_name)
            if len(svc.units) < min_units:
                for idx in range((min_units-len(svc.units))):
                    self.add_unit(svc)

    def get_service(self, service_name):
        svc = self.env_get_service(service_name)
        return {u'Service': service_name,
                u'Charm': parse_charm_url(svc.charm_url).name,
                u'Config': self.get_config(service_name)['Config'],
                # TODO make copy when this is actualized.
                u'Constraints': svc.constraints}

    def get_config(self, service_name):
        svc = self.env_get_service(service_name)
        charm = self._charms.get_charm(svc.charm_url)
        cfg = charm.get_defaults()
        cfg.update(svc.config)
        return {u'Config': cfg}

    def set_config(self, service_name, config):
        svc = self.env_get_service(service_name)
        charm = self._charms.get_charm(svc.charm_url)
        charm.validate(config)
        if svc.config != config:
            svc['config'].update(config)
            self._watches.notify(svc.format_event())
        return {}

    def unset_config(self, service_name, config_keys):
        svc = self.env_get_service(service_name)
        changed = False
        for k in config_keys:
            if k in svc.config:
                del svc.config[k]
                changed = True

        if changed:
            self._watches.notify(svc.format_event())

    def set_charm(self, service_name, charm_url, force=False):
        svc = self.env_get_service(service_name)
        charm = self._charms.get(charm_url)

        if not charm:
            raise EnvError(
                {'Error': 'could not download charm %r' % charm_url})
        tgt_url = parse_charm_url(charm.charm_url)
        svc_url = parse_charm_url(svc.charm_url)

        if tgt_url == svc_url:
            return {}

        # interesting core bug being mirrored, can downgrade without force
        if (tgt_url.get_path(revision=False)
                != svc_url.get_path(revision=False)):
            if not force:
                raise EnvError({'Error': 'cannot upgrade service %r to %r' % (
                    svc.name, charm_url)})
        svc['charm_url'] = charm.charm_url
        self._watches.notify(svc.format_event())
        for u in svc.units.values():
            u['charm_url'] = charm.charm_url
            self._watches.notify(u.format_event())
        return {}

    def set_constraints(self, service_name, constraints):
        svc = self.env_get_service(service_name)
        if svc.constraints == constraints:
            return
        svc['constraints'] = constraints
        self._watches.notify(svc.format_event())
        return {}

    def destroy_service(self, service_name):
        svc = self.env_get_service(service_name)
        remove = []
        for rid, r in self._relations.items():
            for ep in r.endpoints:
                if ep['service'] == service_name:
                    remove.append(rid)
        self.remove_units(svc.units.keys())
        del self._services[svc.name]
        self._watches.notify(svc.format_event('removed'))

    def expose(self, service_name):
        svc = self._services[self._validate_service(service_name)]
        if svc.exposed is True:
            return {}
        svc['exposed'] = True
        self._watches.notify(svc.format_event())
        return {}

    def unexpose(self, service_name):
        svc = self._services[self._validate_service(service_name)]
        if not svc.exposed:
            return {}
        svc['exposed'] = False
        self._watches.notify(svc.format_event())
        return {}

    def add_unit(self, service_name, machine_spec=None, count=1):
        for i in range(count):
            self._add_unit(service_name, machine_spec)

    def _add_unit(self, service_name, machine_spec=None, _subadd=False):

        svc = self.env_get_service(service_name)
        if svc.subordinate and not _subadd:
            # Technically we could if there was an extant host / ie.
            # destroy/remove a previous subordinate unit.
            raise EnvError({'Error': 'Cannot add unit to subordinate'})

        if machine_spec is not None:
            # TODO Verify if subtly different then add-machine, in
            # that naked container types not supported ?? Else
            # refactor into _process_placement
            p = self._validate_placement(
                self._parse_machine_spec(machine_spec))
            if p.machine:
                m = self.env_resolve_machine(p.machine)
            else:
                raise EnvError({'Error': 'Unit placement requires machine'})
            if p.container_type:
                m = self._add_container(
                    m, svc.series, svc.constraints, p.container_type)
        else:
            # Find best machine to put the unit, or add a new machine.
            m = self._match_extant_machines(svc.series, svc.constraints)
            if m is None:
                mid = self.add_machine(svc.series, svc.constraints)['Machine']
                m = self.env_resolve_machine(mid)

        u = svc.add_unit(m)
        self._watches.notify(u.format_event())
        m['dirty'] = True
        return {'Units': [u.id]}

    def _match_extant_machines(self, series, constraints):
        avail = [
            m for m in self._all_machines()
            if not m.dirty and m.series == series
            and constraints.satisfied_by(m.constraints)]
        avail.sort(lambda x, y: cmp(x.constraints, y.constraints))
        if avail:
            return avail[0]

    def _all_machines(self):
        for m in self._machines.values():
            yield m
            for c in m.containers.values():
                yield c

    def remove_units(self, unit_names):
        for uid in unit_names:
            svc_name, _ = uid.split('/')
            svc = self.env_get_service(svc_name)
            u = svc.units[uid]
            for sid, su in svc.units[uid].subordinates.items():
                sub = self.env_get_service(sid.split('/', 1)[0])
                self._sync_sub_unit(u, sub, remove=True)
            svc.remove_unit(uid)
            self._watches.notify(u.format_event('removed'))
        return {}

    def resolved(self, unit_name, retry=False):
        svc_name, _ = unit_name.split('/')
        svc = self.env_get_service(svc_name)
        if not unit_name in svc.units:
            raise EnvError({"Error": u'unit "%s" not found' % unit_name})
        u = svc.units[unit_name]
        u['agent_state'] = Lifecycle.started
        self._watches.notify(u.format_event())
        return {}

    def get_annotation(self, entity, entity_type):
        key = entity_type + '-' + entity.replace("/", "-")
        return {u'Annotations': self._annotations.get(key, {})}

    def set_annotation(self, entity, entity_type, annotation):
        key = entity_type + '-' + entity.replace("/", "-")
        # All annotations are implicitly converted to strings IRL.
        d = {}
        for k, v in annotation.items():
            if not isinstance(v, basestring):
                v = unicode(v)
            d[k] = v
        self._annotations[key] = d
        self._watches.notify(Event(
            u'annotation', Lifecycle.changed, key,
            {u'Annotations': d, u'Tag': key}))
        return {}

    def _validate_service(self, service_name):
        if service_name not in self._services:
            raise EnvError({'Error': 'service %r not found' % service_name})
        return service_name

    def _validate_machine(self, machine_id):
        if machine_id not in self._machines:
            raise EnvError({'Error': 'machine %r not found' % machine_id})
        return machine_id

    # Public Helpers / Not Part of Env Client API / Prefixed with 'env_'

    def env_get_service(self, service_name):
        self._validate_service(service_name)
        return self._services.get(service_name)

    def env_resolve_machine(self, m, parent=False):
        """Resolve a machine or contianer to its db object."""
        if m.isdigit():
            return self._machines[self._validate_machine(m)]

        if not '/' in m:
            raise EnvError({'Error': 'Invalid machine specified %s' % m})
        parts = m.split('/')
        cur = self._machines[self._validate_machine(parts[0])]

        if parent:
            parts = parts[:-2]

        for idx, p in enumerate(parts):
            if idx == 0:
                continue
            elif p in CONTAINER_TYPES:
                continue
            cid = "/".join(parts[:idx+1])
            if cid not in cur.containers:
                raise EnvError({'Error': 'Machine not found %s' % m})
            cur = cur.containers[cid]
        return cur


class EndpointSolver(object):

    def __init__(self, env, charms):
        self.env = env
        self.charms = charms

    # Relation endpoint match logic
    def solve(self, ep_a, ep_b):
        service_a, charm_a, endpoints_a = self._parse_endpoints(ep_a)
        service_b, charm_b, endpoints_b = self._parse_endpoints(ep_b)
        pairs = self._select_endpoint_pairs(endpoints_a, endpoints_b)
        return service_a, service_b, pairs

        return service_a, pairs[0], service_b, pairs[1]

    def _check_endpoints_match(self, ep_a, ep_b):
        if ep_a['interface'] != ep_b['interface']:
            return False
        if ep_a['role'] == 'requirer' and ep_b['role'] == 'provider':
            return True
        elif ep_a['role'] == 'provider' and ep_b['role'] == 'requirer':
            return True
        elif ep_a['role'] == 'peer' and ep_b['role'] == 'peer':
            if ep_a['service'] == ep_b['service']:
                return True
        return False

    def _select_endpoint_pairs(self, eps_a, eps_b):
        pairs = []
        for ep_a in eps_a:
            for ep_b in eps_b:
                if self._check_endpoints_match(ep_a, ep_b):
                    scope = 'global'
                    if (ep_a['scope'] == 'container' or
                            ep_b['scope'] == 'container'):
                        scope = 'container'
                    pairs.append((ep_a, ep_b, scope))
        return pairs

    def _parse_endpoints(self, descriptor):
        if ':' in descriptor:
            svc_name, rel_name = descriptor.split(u":")
        else:
            svc_name, rel_name = unicode(descriptor), None

        svc = self.env.env_get_service(svc_name)
        charm = self.charms.get(svc.charm_url)

        endpoints = []
        found = False
        for ep in charm.endpoints:
            ep['service'] = svc_name
            if rel_name:
                if ep['name'] == rel_name:
                    found = True
                    endpoints.append(ep)
                    break
            else:
                endpoints.append(ep)
        if rel_name and not found:
            raise EnvError({'Error': '%s rel endpoint not valid' % descriptor})

        return svc, charm, endpoints


class CharmRepository(object):
    """A facade to a collection of local and store charms. Local charms
    are referenced from a charm repository directory, store charms are
    referenced by ambigious name.

    Facilitates access to metadata required for verifying relations
    and service config.
    """

    STORE_ENDPOINT = "https://api.jujucharms.com/v4"

    def __init__(self, repo_dir, store_endpoint=None):
        self.repo_dir = repo_dir
        self.endpoint = store_endpoint or self.STORE_ENDPOINT
        self.store_charms = {}
        self.local_charms = {}
        self.local_charm_sequence = 0

    def add_charm(self, charm_ident):
        """Add a store charm charm."""
        charm_url = parse_charm_url(charm_ident)
        if charm_url.path in self.store_charms:
            return self.store_charms[charm_url.path]
        info = self.fetch_store_charm(charm_url)
        self.store_charms[charm_url.path] = info

    def fetch_local_charm(self, charm_url):
        charm_dir = os.path.join(
            self.repo_dir, charm_url.get_path(revision=False)[1:])
        md_path = os.path.join(charm_dir, 'metadata.yaml')
        cfg_path = os.path.join(charm_dir, 'config.yaml')

        if not os.path.exists(md_path):
            raise CharmURLError(charm_url.url, "Not Found @ %s" % charm_dir)
        info = {'config': {}}
        with open(md_path) as fh:
            info['metadata'] = yaml_load(fh.read())
        if os.path.exists(cfg_path):
            with open(cfg_path) as fh:
                info['config'] = yaml_load(fh.read())
        # match revision means nothing to core behavioe
        info['charm_url'] = charm_url.with_revision(
            self.local_charm_sequence).url
        self.local_charm_sequence += 1
        return info

    def fetch_store_charm(self, charm_url):
        info = {}
        md_url = (
            "%s%s/meta/any?include=charm-config"
            "&include=charm-metadata") % (self.endpoint, charm_url.path)
        try:
            fh = urllib2.urlopen(md_url)
        except urllib2.HTTPError, e:
            if e.code == 404:
                raise CharmURLError(charm_url.url, e.msg)
            raise

        with contextlib.closing(fh) as fh:
            raw = json.loads(fh.read())
            info['charm_url'] = raw['Id']
            info['metadata'] = normalize(raw['Meta']['charm-metadata'])
            info['config'] = normalize(raw['Meta']['charm-config'])
        return info

    def get(self, charm_ident):
        charm_url = parse_charm_url(charm_ident)
        if charm_url.scheme == 'local':
            return Charm(self.fetch_local_charm(charm_url))
        return Charm(self.store_charms.get(charm_url.path))


class CharmURLError(Exception):
    """ Mal-formed charm url"""

    def __init__(self, url, message):
        self.url = url
        self.message = message

    def __str__(self):
        return "Bad charm URL %r: %s" % (self.url, self.message)


class CharmURL(
    collections.namedtuple(
        'CharmURL_', ['scheme', 'user', 'series', 'name', 'revision'])):

    def with_revision(self, revision):
        return CharmURL(
            self.scheme, self.user, self.series, self.name, revision)

    def get_path(self, revision=True):
        p = ""
        if self.user:
            p += "/~%s" % self.user
        if self.series:
            p += "/%s" % self.series
        p += "/%s" % self.name
        if revision and self.revision is not None:
            p += "-%d" % self.revision
        return p

    @property
    def path(self):
        return self.get_path()

    @property
    def url(self):
        return "%s:%s" % (self.scheme, self.path.strip("/"))


def normalize(d, keyfunc='lower'):
    r = {}
    for k, v in d.items():
        if isinstance(v, dict):
            v = normalize(v)
        r[getattr(k, keyfunc)()] = v
    return r


# TODO move to classmethod as CharmURL.parse
def parse_charm_url(url):

    def fail(msg):
        raise CharmURLError(url, msg)

    # Scheme
    parts = url.split(":", 1)
    scheme = len(parts) == 1 and 'cs' or parts.pop(0)

    rest = parts[0]
    if scheme not in ("cs", "local"):
        fail("invalid schema")
    if not parts:
        fail("invalid url")

    parts = rest.split("/")
    if len(parts) > 3:
        fail("invalid form")

    user = None
    if parts[0].startswith("~"):
        if scheme == "local":
            fail("users not allowed in local URLs")
        user = parts[0][1:]
        parts = parts[1:]

    if len(parts) != 2:
        if scheme == "local":
            fail("invalid form")
        parts.insert(0, None)
    elif not parts[0].isalpha():
        fail("invalid series")

    revision = None
    series, name = parts

    if "-" in name:
        maybe_name, maybe_revision = name.rsplit("-", 1)
        if maybe_revision.isdigit():
            name, revision = maybe_name, int(maybe_revision)

    return CharmURL(scheme, user, series, name, revision)


Placement = collections.namedtuple(
    'Placement', ['machine_spec', 'container_type', 'machine',
                  'placement_type', 'placement_value'])


class ConstraintError(Exception):

    def __init__(self, msg, value):
        self.msg = msg
        self.value = value

    def __str__(self):
        return "%s: %r" % (self.msg, self.value)


VALID_CONSTRAINTS = [
    ("arch", basestring),
    ('mem', int),
    ('cpu-cores', int),
    ('root-disk', int),
    ('instance-type', basestring),
    ('tags', list),
    ('container', basestring),
    ('cpu-power', int),
    ('networks', list)]


class Constraints(collections.namedtuple(
        "Constraints_", [
        c.replace('-', '_') for c, type_ in VALID_CONSTRAINTS])):

    @classmethod
    def actualize(cls, constraints):
        if constraints is None:
            return None

        def fail(msg):
            raise ConstraintError(msg, constraints)

        if isinstance(constraints, basestring):
            fail("constraints must be specified as struct")
        for n, t in VALID_CONSTRAINTS:
            if n in constraints:
                if not isinstance(constraints[n], t):
                    fail("invalid value for constraints %s" % n)

        if 'container' in constraints:
            if not constraints['container'] in CONTAINER_TYPES:
                fail("invalid container type constraint")

        return cls(*[constraints.get(n) for n, _ in VALID_CONSTRAINTS])

    def serialize(self):
        d = {}
        for n, t in VALID_CONSTRAINTS:
            p = n.replace('-', '_')
            v = getattr(self, p)
            if v is None:
                continue
            d[n] = v
        return d

    def format(self):
        s = []
        for n, t in VALID_CONSTRAINTS:
            p = n.replace('-', '_')
            v = getattr(self, p)
            if v is None:
                continue
            if t == int:
                s.append("%s=%s" % (n, v))
            if n == "arch":
                s.append("%s=%s" % (n, v))
        return " ".join(sorted(s))

    def __cmp__(self, other):
        if other is None:
            return 1
        for n, t in VALID_CONSTRAINTS:
            if not t == int:
                continue
            sv = getattr(self, n, None)
            ov = getattr(other, n, None)
            if sv == ov:
                continue
            if sv < ov:
                return -1
            return 1
        return 0

    def satisfied_by(self, other):
        if other is None:
            return False
        for n, t in VALID_CONSTRAINTS:
            sv = getattr(self, n, None)
            ov = getattr(other, n, None)
            if sv is None:
                continue
            if ov is None:
                return False
            if t == int:
                if ov < sv:
                    return False
            if n == 'tags':
                stags = set(sv)
                if not stags.intersection(set(ov)) == stags:
                    return False
            # TODO care about networks..
        return True
