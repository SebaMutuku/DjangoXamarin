# -*- coding: utf-8 -*-


from django.conf import settings
from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.db import models
#from oauth2client.contrib.django_util.models import CredentialsField

User = settings.AUTH_USER_MODEL


class AddUsersIntoDb(BaseUserManager):
    def create_user(self, email, password=None, is_staff=False, is_admin=False, is_active=False):
        if not email:
            raise ValueError("Email is required")
        else:
            user = self.model(email=self.normalize_email(email), Password=password, )
            user.set_password(password)
            user.save(using=self._db)
        return user

    def create_staffuser(self, email, password=None):
        user = self.create_user(email, password=password, is_staff=True)
        return user

    def create_superuser(self, email, password=None):
        user = self.create_user(email, password=password, is_active=True, is_admin=True, is_staff=True)
        return user

    @staticmethod
    def loginUserIntoModel(email=None, Password=None):
        user = Users.objects.filter(email=email, Password=Password)
        return user or None


class Users(AbstractBaseUser):
    def get_short_name(self):
        full_name = '%s %s' % (self.FirstName, self.SecondName)
        return full_name.strip()

    def get_full_name(self):
        return self.FirstName

    def __str__(self):
        return self.email

    @property
    def token(self):
        return self._generate_jwt_token()

    email = models.EmailField(unique=True, max_length=255, null=False)
    Password = models.CharField(max_length=12000, null=False)
    FirstName = models.CharField(max_length=50, default=None)
    SecondName = models.CharField(max_length=50, default=None)
    RoleId = models.IntegerField(default=1, null=False)
    is_active = models.BooleanField(default=False)
    IsLoggedin = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)
    token = models.CharField(null=True, max_length=255)
    REQUIRED_FIELDS = []
    USERNAME_FIELD = 'email'
    objects = AddUsersIntoDb()


class UserRoles(AbstractBaseUser):
    RoleId = models.IntegerField(default=1, null=False)
    RoleName = models.CharField(max_length=50, default=None)


class googleModel(models.Model):
    email = models.EmailField(unique=True, max_length=255, null=False)
    Username = models.CharField(max_length=12000, null=False)
    Expiry_time=models.CharField(max_length=20,null=False)
    access_token=models.CharField(max_length=255)
    token_type=models.CharField(max_length=20)
