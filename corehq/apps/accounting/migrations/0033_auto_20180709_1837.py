# Generated by Django 1.11.14 on 2018-07-09 18:37

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('accounting', '0032_customerinvoice_squashed_0036_customerbillingrecord'),
    ]

    operations = [
        migrations.RenameField(
            model_name='billingaccount',
            old_name='billing_admin_emails',
            new_name='enterprise_admin_emails',
        ),
    ]
