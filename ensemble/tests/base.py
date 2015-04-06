import unittest
import tempfile
import pprint
import shutil
import os

from ..utils import yaml_dump

TEST_OFFLINE = ("DEB_BUILD_ARCH" in os.environ or "TEST_OFFLINE" in os.environ)


class Base(unittest.TestCase):

    def mkdir(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        return d

    def change_environment(self, **kw):
        """
        """
        original_environ = dict(os.environ)

        @self.addCleanup
        def cleanup_env():
            os.environ.clear()
            os.environ.update(original_environ)

        os.environ.update(kw)

    def write_local_charm(self, md, config=None, actions=None):
        charm_dir = os.path.join(self.repo_dir, md['series'], md['name'])
        if not os.path.exists(charm_dir):
            os.makedirs(charm_dir)
        md_path = os.path.join(charm_dir, 'metadata.yaml')
        with open(md_path, 'w') as fh:
            fh.write(yaml_dump(md))

        if config is not None:
            cfg_path = os.path.join(charm_dir, 'config.yaml')
            with open(cfg_path, 'w') as fh:
                fh.write(yaml_dump(config))

        if actions is not None:
            act_path = os.path.join(charm_dir, 'actions.yaml')
            with open(act_path, 'w') as fh:
                fh.write(yaml_dump(actions))

    def pprint(self, d):
        pprint.pprint(d)
