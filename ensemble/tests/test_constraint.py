from ..core.constraint import Constraints, ConstraintError

from base import Base


class ConstraintTest(Base):

    def test_actualize(self):
        x = Constraints.actualize(
            {'mem': 2000, 'cpu-cores': 4, 'root-disk': 8192})
        self.assertEqual(x.cpu_cores, 4)
        self.assertEqual(x.mem, 2000)
        self.assertRaises(
            ConstraintError, Constraints.actualize, {'mem': '8G'})

    def test_satisifes(self):
        x = Constraints.actualize({'mem': 8000, 'cpu-cores': 4})
        y = Constraints.actualize({'mem': 4000, 'cpu-cores': 2})

        self.assertEqual(x.format(), "cpu-cores=4 mem=8000")
        self.assertEqual(
            x.serialize(), {'mem': 8000, 'cpu-cores': 4})
        self.assertTrue(y.satisfied_by(x))
        self.assertFalse(x.satisfied_by(y))

        x = Constraints.actualize({'tags': ['super', 'special']})
        y = Constraints.actualize({'tags': ['super']})

        self.assertTrue(y.satisfied_by(x))
        self.assertFalse(x.satisfied_by(y))
