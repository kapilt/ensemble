import collections

from models import CONTAINER_TYPES


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
