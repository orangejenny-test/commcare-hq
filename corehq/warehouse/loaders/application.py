from corehq.apps.app_manager.models import Application
from corehq.warehouse.const import APPLICATION_STAGING_SLUG, APPLICATION_DIM_SLUG
from corehq.warehouse.dbaccessors import get_application_ids_by_last_modified
from corehq.warehouse.etl import HQToWarehouseETLMixin, CustomSQLETLMixin
from corehq.warehouse.loaders.base import BaseStagingLoader, BaseLoader
from corehq.warehouse.models import ApplicationStagingTable, ApplicationDim
from dimagi.utils.couch.database import iter_docs


class ApplicationStagingLoader(BaseStagingLoader, HQToWarehouseETLMixin):
    """
    Represents the staging table to dump data before loading into the ApplicationDim

    Grain: application_id
    """
    slug = APPLICATION_STAGING_SLUG
    model_cls = ApplicationStagingTable

    @classmethod
    def field_mapping(cls):
        return [
            ('_id', 'application_id'),
            ('domain', 'domain'),
            ('name', 'name'),
            ('last_modified', 'application_last_modified'),
            ('doc_type', 'doc_type'),
            ('version', 'version'),
            ('copy_of', 'copy_of'),
        ]

    @classmethod
    def dependencies(cls):
        return []

    @classmethod
    def record_iter(cls, start_datetime, end_datetime):
        application_ids = get_application_ids_by_last_modified(start_datetime, end_datetime)

        return iter_docs(Application.get_db(), application_ids)


class ApplicationDimLoader(BaseLoader, CustomSQLETLMixin):
    """
    Dimension for Applications

    Grain: application_id
    """
    slug = APPLICATION_DIM_SLUG
    model_cls = ApplicationDim

    @classmethod
    def dependencies(cls):
        return [APPLICATION_STAGING_SLUG]
