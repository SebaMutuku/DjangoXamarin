# Generated by Django 3.0.6 on 2020-05-04 19:31

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Android', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='userroles',
            name='last_login',
        ),
        migrations.RemoveField(
            model_name='userroles',
            name='password',
        ),
        migrations.AddField(
            model_name='userroles',
            name='username',
            field=models.CharField(default=None, max_length=50),
        ),
    ]
