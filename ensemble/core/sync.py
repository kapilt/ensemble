from env import Environment
from model import Event
from watch import DeltaStream


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
    """Dump current state of the environment as an event stream.

    First pump on any event stream captures current state."""
    w = env.get_watch()
    w.start()
    with w:
        return iter(w).next()


class DeltaApplyHandler(object):
    """

    To keep a bundle we annotate everything we create with
    the bundle id.
    """
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
        # deletes?
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
        svc_name =  u_name.split('/')[0]
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
