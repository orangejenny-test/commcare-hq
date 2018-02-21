from __future__ import absolute_import

import json
from django.test.testcases import TestCase
from django.test.client import RequestFactory
from django.test.testcases import SimpleTestCase
from fakecouch import FakeCouchDb
from corehq.apps.users.models import WebUser

from corehq.apps.domain.models import Domain
from casexml.apps.case.models import CommCareCase
from corehq.apps.userreports.expressions import ExpressionFactory
from corehq.apps.userreports.filters.factory import FilterFactory
from corehq.apps.userreports.models import DataSourceConfiguration
from corehq.apps.userreports.specs import FactoryContext
from corehq.apps.users.models import CommCareUser
from couchforms.models import XFormInstance
import postgres_copy
import sqlalchemy
import os
import mock

from django.test.utils import override_settings
from corehq.apps.userreports.models import StaticDataSourceConfiguration
from corehq.apps.userreports.util import get_indicator_adapter, get_table_name
from corehq.sql_db.connections import connection_manager, UCR_ENGINE_ID


class ChampTestCase(TestCase):

    def setUp(self):
        self.factory = RequestFactory()
        domain = Domain.get_or_create_with_name('champ-cameroon')
        domain.is_active = True
        domain.save()
        self.domain = domain
        user = WebUser.all().first()
        if not user:
            user = WebUser.create(domain.name, 'test', 'passwordtest')
        user.is_authenticated = True
        user.is_superuser = True
        user.is_authenticated = True
        user.is_active = True
        self.user = user


class TestDataSourceExpressions(SimpleTestCase):

    data_source_name = None

    def get_expression(self, column_id, column_type):
        column = self.get_column(column_id)
        if column['type'] == 'boolean':
            return FilterFactory.from_spec(
                column['filter'],
                context=FactoryContext(self.named_expressions, {})
            )
        else:
            self.assertEqual(column['datatype'], column_type)
            return ExpressionFactory.from_spec(
                column['expression'],
                context=FactoryContext(self.named_expressions, {})
            )

    @classmethod
    def setUpClass(cls):
        super(TestDataSourceExpressions, cls).setUpClass()

        data_source_file = os.path.join(
            os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)),
            'ucr_data_sources',
            cls.data_source_name
        )

        with open(data_source_file) as f:
            cls.data_source = DataSourceConfiguration.wrap(json.loads(f.read())['config'])
            cls.named_expressions = cls.data_source.named_expression_objects

    def setUp(self):
        self.database = FakeCouchDb()
        self.case_orig_db = CommCareCase.get_db()
        self.form_orig_db = XFormInstance.get_db()
        self.user_orig_db = CommCareUser.get_db()
        CommCareCase.set_db(self.database)
        XFormInstance.set_db(self.database)
        CommCareUser.set_db(self.database)

    def tearDown(self):
        CommCareCase.set_db(self.case_orig_db)
        XFormInstance.set_db(self.form_orig_db)
        CommCareUser.set_db(self.user_orig_db)

    def get_column(self, column_id):
        return [
            ind
            for ind in self.data_source.configured_indicators
            if ind['column_id'] == column_id
        ][0]
