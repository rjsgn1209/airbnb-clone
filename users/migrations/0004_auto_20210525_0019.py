# Generated by Django 2.2.5 on 2021-05-24 15:19

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0003_auto_20210524_2313'),
    ]

    operations = [
        migrations.RenameField(
            model_name='user',
            old_name='email_confirmed',
            new_name='email_verified',
        ),
    ]