from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.db import models

from DjangoXamarin import settings

User = settings.AUTH_USER_MODEL
Role = settings.AUTH_ROLE_MODEL


class AndroidGooglemodel(models.Model):
    email = models.CharField(unique=True, max_length=255)
    username = models.CharField(db_column='Username', max_length=12000)  # Field name made lowercase.
    expiry_time = models.CharField(db_column='Expiry_time', max_length=20)  # Field name made lowercase.
    access_token = models.CharField(max_length=255)
    token_type = models.CharField(max_length=20)

    class Meta:
        managed = False
        db_table = 'Android_googlemodel'


class AndroidRoles(models.Model):
    roleid = models.IntegerField(db_column='RoleId')  # Field name made lowercase.
    roletype = models.CharField(db_column='RoleType', max_length=50)  # Field name made lowercase.

    class Meta:
        managed = False
        db_table = 'Android_roles'


class AddUsersIntoDb(BaseUserManager):
    def create_user(self, email, password, **extra_fields):
        if not email:
            raise ValueError("Email is required")
        else:
            user = AndroidUsers.objects.create(email=email,
                                               firstname=extra_fields.get('firstname'),
                                               lastname=extra_fields.get('firstname'),
                                               roleid=extra_fields.get('roleid'), )
            user.set_password(password)
        return user

    def create_staffuser(self, email, password=None, firstname=None, lastname=None):
        user = self.create_user(email, password=password, firstname=firstname, LastName=lastname, roleid=2)
        user.is_staff = True
        user.is_admin = False
        user.save()
        return user

    def create_superuser(self, email, password=None, firstname=None, lastname=None):
        user = self.create_user(email, password=password, firstname=firstname, lastname=lastname, is_active=True,
                                is_admin=True, roleid=1)
        user.is_staff = True
        user.is_admin = True
        user.save()
        return user

    def create_normal_user(self, email, password=None, firstname=None, lastname=None):
        user = self.create_user(email, password=password, firstname=firstname, lastname=lastname, roleid=3)
        user.is_staff = False
        user.is_admin = False
        user.save()
        return user

    @staticmethod
    def loginUserIntoModel(email=None, pasword=None):
        user = AndroidUsers.objects.filter(email=email, pasword=pasword)
        return user or None


class AndroidUsers(AbstractBaseUser):
    def get_full_name(self):
        full_name = '%s %s' % (self.firstname, self.lastname)
        return full_name.strip()

    def get_short_name(self):
        return self.firstname

    def __str__(self):
        return self.email

    @property
    def getToken(self):
        return self.token

    password = models.CharField(max_length=255)
    last_login = models.CharField(max_length=255, blank=True, null=True)
    email = models.CharField(unique=True, max_length=255)
    firstname = models.CharField(max_length=50)
    lastname = models.CharField(max_length=50)
    is_active = models.BooleanField()
    logged_in = models.BooleanField()
    is_staff = models.BooleanField()
    is_admin = models.BooleanField()
    token = models.CharField(max_length=255, blank=True, null=True)
    REQUIRED_FIELDS = []
    USERNAME_FIELD = 'email'
    role = models.OneToOneField(
        AndroidRoles,
        on_delete=models.CASCADE,
        primary_key=True,
    )

    class Meta:
        managed = False
        db_table = 'Android_users'


class AuthGroup(models.Model):
    name = models.CharField(unique=True, max_length=150)

    class Meta:
        managed = False
        db_table = 'auth_group'


class AuthGroupPermissions(models.Model):
    group = models.ForeignKey(AuthGroup, models.DO_NOTHING)
    permission = models.ForeignKey('AuthPermission', models.DO_NOTHING)

    class Meta:
        managed = False
        db_table = 'auth_group_permissions'
        unique_together = (('group', 'permission'),)


class AuthPermission(models.Model):
    name = models.CharField(max_length=255)
    content_type = models.ForeignKey('DjangoContentType', models.DO_NOTHING)
    codename = models.CharField(max_length=100)

    class Meta:
        managed = False
        db_table = 'auth_permission'
        unique_together = (('content_type', 'codename'),)


class AuthtokenToken(models.Model):
    key = models.CharField(primary_key=True, max_length=40)
    created = models.DateTimeField()
    user = models.OneToOneField(AndroidUsers, models.DO_NOTHING)

    class Meta:
        managed = False
        db_table = 'authtoken_token'


class DjangoAdminLog(models.Model):
    action_time = models.DateTimeField()
    object_id = models.TextField(blank=True, null=True)
    object_repr = models.CharField(max_length=200)
    action_flag = models.SmallIntegerField()
    change_message = models.TextField()
    content_type = models.ForeignKey('DjangoContentType', models.DO_NOTHING, blank=True, null=True)
    user = models.ForeignKey(AndroidUsers, models.DO_NOTHING)

    class Meta:
        managed = False
        db_table = 'django_admin_log'


class DjangoContentType(models.Model):
    app_label = models.CharField(max_length=100)
    model = models.CharField(max_length=100)

    class Meta:
        managed = False
        db_table = 'django_content_type'
        unique_together = (('app_label', 'model'),)


class DjangoMigrations(models.Model):
    app = models.CharField(max_length=255)
    name = models.CharField(max_length=255)
    applied = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'django_migrations'


class DjangoSession(models.Model):
    session_key = models.CharField(primary_key=True, max_length=40)
    session_data = models.TextField()
    expire_date = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'django_session'


class Oauth2ProviderAccesstoken(models.Model):
    id = models.BigAutoField(primary_key=True)
    token = models.CharField(unique=True, max_length=255)
    expires = models.DateTimeField()
    scope = models.TextField()
    application = models.ForeignKey('Oauth2ProviderApplication', models.DO_NOTHING, blank=True, null=True)
    user = models.ForeignKey(AndroidUsers, models.DO_NOTHING, blank=True, null=True)
    created = models.DateTimeField()
    updated = models.DateTimeField()
    source_refresh_token = models.OneToOneField('Oauth2ProviderRefreshtoken', models.DO_NOTHING, blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'oauth2_provider_accesstoken'


class Oauth2ProviderApplication(models.Model):
    id = models.BigAutoField(primary_key=True)
    client_id = models.CharField(unique=True, max_length=100)
    redirect_uris = models.TextField()
    client_type = models.CharField(max_length=32)
    authorization_grant_type = models.CharField(max_length=32)
    client_secret = models.CharField(max_length=255)
    name = models.CharField(max_length=255)
    user = models.ForeignKey(AndroidUsers, models.DO_NOTHING, blank=True, null=True)
    skip_authorization = models.BooleanField()
    created = models.DateTimeField()
    updated = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'oauth2_provider_application'


class Oauth2ProviderGrant(models.Model):
    id = models.BigAutoField(primary_key=True)
    code = models.CharField(unique=True, max_length=255)
    expires = models.DateTimeField()
    redirect_uri = models.CharField(max_length=255)
    scope = models.TextField()
    application = models.ForeignKey(Oauth2ProviderApplication, models.DO_NOTHING)
    user = models.ForeignKey(AndroidUsers, models.DO_NOTHING)
    created = models.DateTimeField()
    updated = models.DateTimeField()
    code_challenge = models.CharField(max_length=128)
    code_challenge_method = models.CharField(max_length=10)

    class Meta:
        managed = False
        db_table = 'oauth2_provider_grant'


class Oauth2ProviderRefreshtoken(models.Model):
    id = models.BigAutoField(primary_key=True)
    token = models.CharField(max_length=255)
    access_token = models.OneToOneField(Oauth2ProviderAccesstoken, models.DO_NOTHING, blank=True, null=True)
    application = models.ForeignKey(Oauth2ProviderApplication, models.DO_NOTHING)
    user = models.ForeignKey(AndroidUsers, models.DO_NOTHING)
    created = models.DateTimeField()
    updated = models.DateTimeField()
    revoked = models.DateTimeField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'oauth2_provider_refreshtoken'
        unique_together = (('token', 'revoked'),)
