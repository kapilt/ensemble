import StringIO
import pprint


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
