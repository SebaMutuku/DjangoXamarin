# # -*- coding: utf-8 -*-
#
#
# from django.conf import settings
# from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
# from django.db import models
#
# User = settings.AUTH_USER_MODEL
# Role = settings.AUTH_ROLE_MODEL
#
#
# class AddUsersIntoDb(BaseUserManager):
#     def create_user(self, email, password, **extra_fields):
#         if not email:
#             raise ValueError("Email is required")
#         else:
#             user = Users.objects.create(email=email,
#                                         firstname=extra_fields.get('firstname'),
#                                         lastname=extra_fields.get('firstname'),
#                                         roleid=extra_fields.get('roleid'), )
#             user.set_password(password)
#         return user
#
#     def create_staffuser(self, email, password=None, firstname=None, lastname=None):
#         user = self.create_user(email, password=password, firstname=firstname, LastName=lastname, roleid=2)
#         user.is_staff = True
#         user.is_admin = False
#         user.save()
#         return user
#
#     def create_superuser(self, email, password=None, firstname=None, lastname=None):
#         user = self.create_user(email, password=password, firstname=firstname, lastname=lastname, is_active=True,
#                                 is_admin=True, roleid=1)
#         user.is_staff = True
#         user.is_admin = True
#         user.save()
#         return user
#
#     def create_normal_user(self, email, password=None, firstname=None, lastname=None):
#         user = self.create_user(email, password=password, firstname=firstname, lastname=lastname, roleid=3)
#         user.is_staff = False
#         user.is_admin = False
#         user.save()
#         return user
#
#     @staticmethod
#     def loginUserIntoModel(email=None, pasword=None):
#         user = Users.objects.filter(email=email, pasword=pasword)
#         return user or None
#
#
# class Users(AbstractBaseUser):
#     def get_full_name(self):
#         full_name = '%s %s' % (self.firstname, self.lastname)
#         return full_name.strip()
#
#     def get_short_name(self):
#         return self.firstname
#
#     def __str__(self):
#         return self.email
#
#     @property
#     def getToken(self):
#         return self.token
#
#     email = models.EmailField(unique=True, max_length=255, null=False)
#     password = models.CharField(max_length=255, null=False)
#     firstname = models.CharField(max_length=50, default=None)
#     lastname = models.CharField(max_length=50, default=None)
#     is_active = models.BooleanField(default=True)
#     logged_in = models.BooleanField(default=False)
#     last_login = models.CharField(max_length=255,default=None,null=True)
#     is_staff = models.BooleanField(default=False)
#     is_admin = models.BooleanField(default=False)
#     token = models.CharField(null=True, max_length=255)
#     roleid = models.IntegerField()
#     REQUIRED_FIELDS = []
#     USERNAME_FIELD = 'email'
#     objects = AddUsersIntoDb()
#
#
# class Roles(models.Model):
#     roleid = models.IntegerField(null=False)
#     RoleType = models.CharField(max_length=50, default=None)
#
#
# class googleModel(models.Model):
#     email = models.EmailField(unique=True, max_length=255, null=False)
#     Username = models.CharField(max_length=12000, null=False)
#     Expiry_time = models.CharField(max_length=20, null=False)
#     access_token = models.CharField(max_length=255)
#     token_type = models.CharField(max_length=20)
