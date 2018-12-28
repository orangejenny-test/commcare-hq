from __future__ import absolute_import
from __future__ import unicode_literals
from django.urls import reverse
from django.http import HttpResponseRedirect
from django.utils.decorators import method_decorator
from django.views.generic import *
from corehq.apps.styleguide.palette import (
    PaletteColor,
    PaletteColorGroup,
    Palette,
)
from corehq.apps.styleguide.example_forms import BasicCrispyForm


def styleguide_default(request):
    return HttpResponseRedirect(reverse(MainStyleGuideView.urlname))


class MainStyleGuideView(TemplateView):
    template_name = 'styleguide/pages/home.html'
    urlname = 'styleguide_home'


class BaseStyleGuideArticleView(TemplateView):
    template_name = 'styleguide/base_section.html'

    @property
    def sections(self):
        """This will be inserted into the page context's sections variable
        as a list of strings following the format
        'styleguide/_includes/<section>.html'
        Make sure you create the corresponding template in the styleguide app.

        :return: List of the sections in order. Usually organized by
        <article>/<section_name>
        """
        raise NotImplementedError("please implement 'sections'")

    @property
    def navigation_name(self):
        """This will be inserted into the page context under
        styleguide/_includes/nav/<navigation_name>.html. Make sure
        you create the corresponding template in the styleguide app
        when you add this.
        :return: a string that is the name of the navigation section
        """
        raise NotImplementedError("please implement 'navigation_name'")

    @property
    def section_context(self):
        return {
            'sections': ['styleguide/_includes/%s.html' % s
                         for s in self.sections],
            'navigation': ('styleguide/_includes/nav/%s.html'
                           % self.navigation_name),
        }

    @property
    def page_context(self):
        """It's intended that you override this method when necessary to provide
        any additional content that's relevant to the view specifically.
        :return: a dict
        """
        return {}

    def render_to_response(self, context, **response_kwargs):
        context.update(self.section_context)
        context.update(self.page_context)
        return super(BaseStyleGuideArticleView, self).render_to_response(
            context, **response_kwargs)


class AtomsStyleGuideView(BaseStyleGuideArticleView):
    urlname = 'styleguide_atoms'
    navigation_name = 'atoms'

    @property
    def sections(self):
        return [
            'atoms/intro',
            'atoms/accessibility',
            'atoms/typography',
            'atoms/colors',
            'atoms/icons',
            'atoms/css',
        ]

    @property
    def page_context(self):
        return {
            'icons': {
                'HQ General Icons': [
                    'fcc-flower', 'fcc-applications', 'fcc-commtrack', 'fcc-reports', 'fcc-data', 'fcc-users',
                    'fcc-settings', 'fcc-help', 'fcc-exchange', 'fcc-messaging', 'fcc-chart-report',
                    'fcc-form-report', 'fcc-datatable-report', 'fcc-piegraph-report', 'fcc-survey', 'fcc-casemgt',
                    'fcc-blankapp', 'fcc-globe', 'fcc-app-createform', 'fcc-app-updateform',
                    'fcc-app-completeform',
                ],
                'Form Builder Icons': [
                    'fcc-fd-text', 'fcc-fd-numeric', 'fcc-fd-data', 'fcc-fd-variable', 'fcc-fd-single-select',
                    'fcc-fd-single-circle', 'fcc-fd-multi-select', 'fcc-fd-multi-box', 'fcc-fd-decimal',
                    'fcc-fd-long', 'fcc-fd-datetime', 'fcc-fd-audio-capture', 'fcc-fd-android-intent',
                    'fcc-fd-signature', 'fcc-fd-multi-box', 'fcc-fd-single-circle', 'fcc-fd-hash',
                    'fcc-fd-external-case', 'fcc-fd-external-case-data', 'fcc-fd-expand', 'fcc-fd-collapse',
                    'fcc-fd-case-property', 'fcc-fd-edit-form',
                ],
            },
            'palette': self.palette,
        }

    @property
    def palette(self):
        text_color = PaletteColor('1c2126',)
        bg_color = PaletteColor('f2f2f1',)

        neutrals = PaletteColorGroup(
            "Neutral",
            'neutral',
            PaletteColor('685c53',),
            PaletteColor('d6d6d4', name="Light"),
            PaletteColor('373534', name="Dark"),
        )

        brand = PaletteColorGroup(
            "Brand",
            'brand',
            PaletteColor('004ebc',),
            PaletteColor('bcdeff', name="Light"),
            PaletteColor('002c5f', name="Dark"),
        )

        light_cool_accent = PaletteColorGroup(
            "Light Cool Accent",
            'light-cool-accent',
            PaletteColor('00bdc5',),
            PaletteColor('ccf3f4', name="Light"),
            PaletteColor('00799a', name="Dark"),
        )

        dark_warm_accent = PaletteColorGroup(
            "Dark Warm Accent",
            'dark-warm-accent',
            PaletteColor('ff8400',),
            PaletteColor('ffe3c2', name="Light"),
            PaletteColor('994f00', name="Dark"),
        )

        light_warm_accent = PaletteColorGroup(
            "Light Warm Accent",
            'light-warm-accent',
            PaletteColor('eec200',),
            PaletteColor('ffea8a', name="Light"),
            PaletteColor('9c6f19', name="Dark"),
        )

        attention_positive = PaletteColorGroup(
            "Attention Positive",
            'att-pos',
            PaletteColor('4aba32',),
            PaletteColor('bbe5b3', name="Light"),
            PaletteColor('118043', name="Dark"),
        )

        attention_negative = PaletteColorGroup(
            "Attention Negative",
            'att-neg',
            PaletteColor('e73c27',),
            PaletteColor('fead9a', name="Light"),
            PaletteColor('bf0712', name="Dark"),
        )

        dark_cool_accent = PaletteColorGroup(
            "Dark Cool Accent",
            'dark-cool-accent',
            PaletteColor('9060c8',),
            PaletteColor('d6c5ea', name="Light"),
            PaletteColor('5d3f82', name="Dark"),
        )

        return Palette(
            [
                neutrals,
                brand,
                light_cool_accent,
                dark_warm_accent,
                light_warm_accent,
                attention_positive,
                attention_negative,
                dark_cool_accent,
            ],
            text_color,
            bg_color,
        )


class MoleculesStyleGuideView(BaseStyleGuideArticleView):
    urlname = 'styleguide_molecules'
    navigation_name = 'molecules'

    @property
    def sections(self):
        return [
            'molecules/intro',
            'molecules/forms',
        ]

    @property
    def page_context(self):
        return {
            'basic_crispy_form': BasicCrispyForm(),
        }


class OrganismsStyleGuideView(BaseStyleGuideArticleView):
    urlname = 'styleguide_organisms'
    navigation_name = 'organisms'

    @property
    def sections(self):
        return [
            'organisms/intro',
            'organisms/views',
        ]
