
import tempfile
import shutil

from charm import CharmRepository, parse_charm_url
from constraints import Constraints
from endpoint import EndpointSolver
from ..errors import EnvError
from model import (
    CONTAINER_TYPES, Machine, Network, Lifecycle, Relation, Service)
from watch import WatchManager


class MemStorage(object):

    # TODO move state/db to separate abstraction.

    def __init__(self, env_name, charms):
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
            # _charm_dir variable won't even exist / attributeerror if
            # not explicitly set.
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



Placement = collections.namedtuple(
    'Placement', ['machine_spec', 'container_type', 'machine',
                  'placement_type', 'placement_value'])


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


