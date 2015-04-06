import collections
import contextlib
import json
import os
import urllib2

from model import Charm
from ..utils import yaml_load


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
