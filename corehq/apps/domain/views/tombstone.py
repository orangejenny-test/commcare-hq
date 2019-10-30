from crispy_forms import layout as crispy
from crispy_forms.helper import FormHelper

from corehq.apps.domain.models import Domain
from corehq.apps.hqwebapp.crispy import FormActions


from django import forms
from django.utils.decorators import method_decorator

from corehq.apps.domain.decorators import require_superuser
from corehq.apps.hqadmin.views import BaseAdminSectionView
from django.utils.translation import ugettext_lazy as _


@method_decorator(require_superuser, name='dispatch')
class TombstoneManagement(BaseAdminSectionView):
    urlname = 'tombstone_management'
    page_title = _("Prevent the use of specific domain names")
    template_name = 'domain/tombstone_management.html'

    form = None
    domain_results = None

    def get_context_data(self, **kwargs):

        return {
            'form': self.form or TombstoneManagementForm(),
            'domains': self.domain_results or [],
        }

    def post(self, request, *args, **kwargs):
        self.form = TombstoneManagementForm(self.request.POST)
        if self.form.is_valid():
            domain_names = self.form.cleaned_data['domains']
            self.domain_results = []
            for domain in domain_names:
                project = Domain.get_by_name(domain)
                self.domain_results.append((domain, project))
        return self.get(request, *args, **kwargs)


class TombstoneManagementForm(forms.Form):
    csv_domain_list = forms.CharField(
        label="Comma separated domains",
        widget=forms.Textarea()
    )

    def clean(self):
        csv_domain_list = self.cleaned_data.get('csv_domain_list', '')
        domains = csv_domain_list.split(',')

        if len(domains) > 10:
            raise forms.ValidationError(
                "This command is intended to create a few tombstones at a time. "
                "If you need to create more than 10, do them in batches."
            )

        self.cleaned_data['domains'] = domains
        return self.cleaned_data

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.helper = FormHelper()
        self.helper.form_class = "form-horizontal"
        self.helper.label_class = 'col-sm-3 col-md-2'
        self.helper.field_class = 'col-sm-9 col-md-8 col-lg-6'
        self.helper.layout = crispy.Layout(
            'csv_domain_list',
            FormActions(
                crispy.Submit(
                    '',
                    'Check Domains'
                )
            )
        )
