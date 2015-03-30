
import yaml

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


def normalize(d, keyfunc='lower'):
    r = {}
    for k, v in d.items():
        if isinstance(v, dict):
            v = normalize(v)
        r[getattr(k, keyfunc)()] = v
    return r
