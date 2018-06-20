import unittest
import sys
sys.path.append('../')
from gluon import current
from gluon.storage import Storage

from controllers import default
class DefaultTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.application = current.app

    def setUp(self):
        """
        """

        self.request = current.request
        self.request.controller = 'default'
        self.request.application = 'darkcloud1'
        self.request.post_vars = Storage()
        self.request.get_vars = Storage()
        self.application.session.clear()
