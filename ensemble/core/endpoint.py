
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
