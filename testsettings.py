from settings import *

INSTALLED_APPS += (
    'django_nose',
)

TEST_RUNNER = 'django_nose.NoseTestSuiteRunner'
NOSE_ARGS = [
    #'--with-doctest', # adds 5s to discovery (before tests start); TODO travis should use it
    '--with-fixture-bundling',
    '--logging-clear-handlers',
    '--ignore-files=^localsettings',
    '--exclude-dir=corehq/apps/cloudcare/tests/selenium',
    '--exclude-dir=corehq/apps/reports/tests/selenium',
    '--exclude-dir=scripts',
]
NOSE_PLUGINS = [
    # Disable migrations by default. Use --with-migrations to enable them.
    'corehq.util.nose.DjangoMigrationsPlugin',
    'corehq.util.nose.OmitDjangoInitModuleTestsPlugin',
]

# shorten nose args displayed in console by putting these in os.environ
os.environ.setdefault('NOSE_DB_TEST_CONTEXT', 'corehq.util.nose.HqdbContext')
os.environ.setdefault(
    'NOSE_NON_DB_TEST_CONTEXT', 'corehq.util.nose.ErrorOnDbAccessContext')

# HqTestSuiteRunner settings
INSTALLED_APPS = INSTALLED_APPS + list(TEST_APPS)
CELERY_ALWAYS_EAGER = True
PILLOWTOPS = {}

# required by auditcare tests
AUDIT_MODEL_SAVE = ['django.contrib.auth.models.User']


def _set_couchdb_test_settings():
    import settingshelper

    def get_test_db_name(dbname):
        return "%s_test" % dbname

    global COUCH_DATABASE_NAME, EXTRA_COUCHDB_DATABASES

    COUCH_DATABASE_NAME = get_test_db_name(COUCH_DATABASE_NAME)
    globals().update(settingshelper.get_dynamic_db_settings(
        COUCH_SERVER_ROOT,
        COUCH_USERNAME,
        COUCH_PASSWORD,
        COUCH_DATABASE_NAME,
    ))

    EXTRA_COUCHDB_DATABASES = {
        db_name: get_test_db_name(url)
        for db_name, url in EXTRA_COUCHDB_DATABASES.items()
    }

_set_couchdb_test_settings()


def _clean_up_logging_output():
    import logging
    logging.getLogger('raven').setLevel('WARNING')

    # make all loggers propagate to prevent
    # "No handlers could be found for logger ..."
    # (a side effect of --logging-clear-handlers)
    for item in LOGGING["loggers"].values():
        if not item.get("propagate", True):
            item["propagate"] = True

_clean_up_logging_output()
