# Generated by Django 3.0.6 on 2020-05-06 18:08

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Android', '0002_auto_20200504_1931'),
    ]

    operations = [
        migrations.CreateModel(
            name='Roles',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('RoleId', models.IntegerField(default=1)),
                ('RoleType', models.CharField(default=None, max_length=50)),
            ],
        ),
        migrations.DeleteModel(
            name='UserRoles',
        ),
    ]
