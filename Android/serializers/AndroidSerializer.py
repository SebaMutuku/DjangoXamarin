import logging
import traceback
from datetime import datetime, timedelta

import jwt
from django.http import HttpResponse
from rest_framework import authentication
from rest_framework import serializers
from rest_framework.pagination import PageNumberPagination

from Android.models import Users as UserModel, Roles as RoleModel, AddUsersIntoDb
from Android.security.Encryption import encrypt, decrypt
from DjangoXamarin import settings

logger = logging.getLogger(__name__)


class LoginSerializer(serializers.Serializer):
    class Meta:

        fields = (
            'email',
            'password'
        )
        model = UserModel

    def checkLoginCredentials(self, data, *args, **kwargs):
        global user
        email = data.get('email')
        # password = pbkdf2_sha256.encrypt(data.get('password'), rounds=36000, salt_size=32)
        password = decrypt(data.get('password'))
        logger.info("Invalid user")

        try:
            user = UserModel.objects.get(email=email, password=password)
            if user is not None:
                if user.is_active:
                    if not user.IsLoggedin:
                        secret_key = settings.SECRET_KEY
                        expirydate = datetime.now() + timedelta(days=60)
                        claims = {
                            "id": user.id,
                            "subject": user.email,
                            "exp": expirydate
                        }
                        token = jwt.encode(claims, secret_key, algorithm='HS256')
                        user.token = token
                        user.IsLoggedin = True
                        user.save()
                    else:
                        raise serializers.ValidationError(
                            {"Message": "User Already Logged in.Logout First", "token": ""})
                else:
                    raise serializers.ValidationError({"Message": "User is Inactive", "token": ""})

            else:
                raise serializers.ValidationError({"Message": "Invalid login Credentials", "token": ""})

        except UserModel.DoesNotExist:
            token = None
        return token


class RegisterSerializer(serializers.ModelSerializer, PageNumberPagination):
    class Meta:
        model = UserModel
        fields = (
            'id',
            'email',
            'firstname',
            'lastname',
            'is_active',
            'logged_in',
            'password',
            'is_admin',
            'is_staff',
            'token'
        )

    def addUser(self, data):
        loggedinuser = "DecodeToken().decodeToken(data)"
        if loggedinuser is not None:
            if data['password'] is None:
                raise serializers.ValidationError({"Message": "Passwords do not match"})
            else:
                from django.core.validators import validate_email
                email = validate_email(data['email'])
                if email is False:
                    raise serializers.ValidationError({"Message": "Please enter a valid email"})
                else:
                    email_exist = UserModel.objects.filter(email=data['email'])
                    if email_exist:
                        raise serializers.ValidationError(
                            {"Message": "User with email " + "[" + str(data['email']) + "]" + " already exists "})
                    else:
                        password = encrypt(data['password'])
                        email = data.get('email')
                        FirstName = data['firstname']
                        SecondName = data['lastname']
                        if self.check_roles(data) is not None:
                            if self.checkRoles(data.get('RoleId')) == "ADMIN":
                                user = AddUsersIntoDb().create_superuser(email=email,
                                                                         password=password,
                                                                         lastname=SecondName,
                                                                         firstname=FirstName)
                            elif self.checkRoles(data.get('RoleId')) == "STAFF":
                                user = AddUsersIntoDb().create_superuser(email=email,
                                                                         password=password,
                                                                         LastName=SecondName,
                                                                         FirstName=FirstName)
                            else:
                                user = AddUsersIntoDb().create_normal_user(email=email,
                                                                           password=password,
                                                                           firstname=FirstName,
                                                                           lastname=SecondName)
                            return user
                        else:
                            raise serializers.ValidationError({"Message": "Missing Role Name"})
                            return  None

    def check_roles(self, roleId):
        try:
            role = RoleModel.objects.get(RoleId=roleId)
            print(str(role))
            if role.RoleType is not None:
                roleName = role.RoleType
            else:
                roleName = None
        except Exception as e:
            logging.getLogger(str("The Exception is: %s".join(e.args)).strip())
            roleName = None
        return roleName


class ListAllUsers(serializers.ModelSerializer, PageNumberPagination):
    class Meta:
        model = UserModel
        fields = (
            'id',
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

    def listUsers(self):
        user = UserModel.objects.all()
        if user is not None:
            return user
        else:
            return user or None

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


class DecodeToken:

    def decodeToken(self, request):
        headers = authentication.get_authorization_header(request).split()
        if not headers or headers[0].lower() != b'token':
            loggedinuser = None
        elif len(headers) == 1:
            msg = 'Invalid token header. No credentials provided.'
            raise jwt.exceptions.AuthenticationFailed(msg)
        elif len(headers) > 2:
            msg = 'Invalid token header'
            raise jwt.exceptions.AuthenticationFailed(msg)
        else:
            try:
                token = headers[1]
                if token is None:
                    msg = 'Invalid token header'
                    raise jwt.exceptions.AuthenticationFailed(msg)
                else:
                    user_data = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
                    user_id = user_data['id']
                    username = user_data['subject']
                    db_user = UserModel.objects.get(user_id=user_id, username=username)
                    if db_user.token == token:
                        loggedinuser = db_user.username
                    else:
                        loggedinuser = None
            except jwt.ExpiredSignature or jwt.DecodeError or jwt.InvalidTokenError:
                return HttpResponse({'Error': "Token is invalid"}, status="403")
            except UserModel.DoesNotExist:
                loggedinuser = None
        return loggedinuser
