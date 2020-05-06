# -*- coding: utf-8 -*-


from django.conf import settings
from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.db import models

# from oauth2client.contrib.django_util.models import CredentialsField

User = settings.AUTH_USER_MODEL


class AddUsersIntoDb(BaseUserManager):
    def create_user(self, email, password=None, firstname=None, lastname=None, is_active=False, is_admin=False,
                    is_staff=False, roleid=None):
        if not email:
            raise ValueError("Email is required")
        else:
            user = self.model(email=self.normalize_email(email), password=password, )
            user.set_password(password)
            user.firstname = firstname
            user.lastname = lastname
            user.is_active = is_active
            user.is_admin = is_admin
            user.is_staff = is_staff
            user.roleid = roleid
            user.save(using=self._db)
        return user

    def create_staffuser(self, email, password=None, firstname=None, lastname=None):
        user = self.create_user(email, password=password, firstname=firstname, LastName=lastname, is_admin=False,
                                is_active=True, is_staff=True, roleid=2)
        return user

    def create_superuser(self, email, password=None, firstname=None, lastname=None):
        user = self.create_user(email, password=password, firstname=firstname, lastname=lastname, is_active=True,
                                is_admin=True, roleid=1)
        return user

    def create_normal_user(self, email, password=None, firstname=None, lastname=None):
        user = self.create_user(email, password=password, firstname=firstname, lastname=lastname, is_active=True,
                                is_admin=False, roleid=3)
        return user

    @staticmethod
    def loginUserIntoModel(email=None, pasword=None):
        user = Users.objects.filter(email=email, pasword=pasword)
        return user or None


class Users(AbstractBaseUser):
    def get_full_name(self):
        full_name = '%s %s' % (self.FirstName, self.SecondName)
        return full_name.strip()

    def get_short_name(self):
        return self.FirstName

    def __str__(self):
        return self.email

    @property
    def token(self):
        return self.token

    email = models.EmailField(unique=True, max_length=255, null=False)
    password = models.CharField(max_length=12000, null=False)
    firstname = models.CharField(max_length=50, default=None)
    lastname = models.CharField(max_length=50, default=None)
    is_active = models.BooleanField(default=True)
    logged_in = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)
    token = models.CharField(null=True, max_length=255)
    roleid = models.IntegerField()
    REQUIRED_FIELDS = []
    USERNAME_FIELD = 'email'
    objects = AddUsersIntoDb()


class Roles(models.Model):
    RoleId = models.IntegerField(null=False)
    RoleType = models.CharField(max_length=50, default=None)


class googleModel(models.Model):
    email = models.EmailField(unique=True, max_length=255, null=False)
    Username = models.CharField(max_length=12000, null=False)
    Expiry_time = models.CharField(max_length=20, null=False)
    access_token = models.CharField(max_length=255)
    token_type = models.CharField(max_length=20)
