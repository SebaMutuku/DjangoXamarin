

import logging

from passlib.handlers.pbkdf2 import pbkdf2_sha256
from rest_framework import serializers
from rest_framework.pagination import PageNumberPagination

from .models import Users as UserModel

logger = logging.getLogger(__name__)


class LoginSerializer(serializers.Serializer):
    class Meta:

        fields = (
            'Username',
            'Password'
        )
        model = UserModel

    def loginUser(self, data):
        username = data.get('Username')
        #password = pbkdf2_sha256.encrypt(data.get('password'), rounds=36000, salt_size=32)
        password=data.get('password')
        query = UserModel.objects.raw("select * from Users")
        print(str(data))
        print("Password is: ", password)
        logger.info("Invalid user")

        try:
            user = UserModel.objects.get(Username=username, Password=password)
            dbPassword = user.Password
            print('Password.......' + str(dbPassword))
            if user is not None:
                user = user
                logging.getLogger( logger.info(user))
            else:
                raise serializers.ValidationError({"Message": "Invalid login Credentials"})

        except UserModel.DoesNotExist:
            user = None
        return user


class RegisterSerializer(serializers.ModelSerializer, PageNumberPagination):
    class Meta:
        model = UserModel
        fields = (
            'id',
            'Username',
            'email',
            'FirstName',
            'SecondName',
            'is_active',
            'IsLoggedin',
            'Password',
            'is_admin',
            'is_staff',
            'token'
        )

    def addUser(self, data):
        # date_now = self.datetime.now()
        if data['Password'] is None:
            raise serializers.ValidationError({"Message": "Passwords do not match"})
        else:
            from django.core.validators import validate_email
            email = validate_email(data['email'])
            if email is False:
                raise serializers.ValidationError({"Message": "Please enter a valid email"})
            else:
                email_exist = UserModel.objects.filter(email=data['email'])
                # username_exist = UserModel.objects.filter(email=data['Username'])
                if email_exist:
                    raise serializers.ValidationError(
                        {"Message": "User with email " + "[" + str(data['email']) + "]" + " already exists "})
                else:
                    password = pbkdf2_sha256.encrypt(data['Password'], rounds=36000, salt_size=32)
                    user = UserModel.objects.create(
                        email=data['email'],
                        Username=data['Username'],
                        Password=data['Password'],
                        FirstName=data['FirstName'],
                        SecondName=data['SecondName'], )
                    user.save()
                return user


class ListAllUsers(serializers.ModelSerializer, PageNumberPagination):
    class Meta:
        model = UserModel
        fields = (
            'id',
            'Username',
            'email',
            'FirstName',
            'SecondName',
            'is_active',
            'IsLoggedin',
            'Password',
            'is_admin',
            'is_staff',
            'token'
        )

    def listUsers(self, data):
        user = UserModel.objects.all()
        if user is not None:
            return user
        else:
            user = None

    def findByEmail(self, data):
        try:
            user = UserModel.objects.get(email=data['email'])
            if user is not None:
                return user
            else:
                user = None
            return user
        except UserModel.DoesNotExist:
            user = None
