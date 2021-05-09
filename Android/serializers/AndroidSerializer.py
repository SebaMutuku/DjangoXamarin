import datetime
import logging
from datetime import datetime, timedelta

import jwt
from django.core.exceptions import ObjectDoesNotExist
from django.http import HttpResponse
from rest_framework import authentication, exceptions
from rest_framework import serializers
from rest_framework.pagination import PageNumberPagination

from Android.models import AndroidUsers as UserModel, AddUsersIntoDb, AndroidRoles
from Android.security.Encryption import encryptRawValues
from DjangoXamarin import settings

logger = logging.getLogger(__name__)


class LoginSerializer(serializers.Serializer):
    def create(self, validated_data):
        pass

    def update(self, instance, validated_data):
        pass

    class Meta:

        fields = (
            'email',
            'password'
        )
        model = UserModel

    @staticmethod
    def checkLoginCredentials(data):
        email = data['email']
        password = data['password']
        logger.info("Invalid user", email, password)

        try:
            user = UserModel.objects.get(email__exact=email)
            encoded_password = encryptRawValues(password)
            if user is not None:
                if user.is_active:
                    # if not user.logged_in != False:
                        if encoded_password == user.password:
                            secret_key = settings.SECRET_KEY
                            expirydate = datetime.now() + timedelta(days=1)
                            claims = {
                                "id": user.role_id,
                                "subject": user.email,
                                "exp": expirydate,
                                "roleId": user.role_id
                            }
                            token = jwt.encode(claims, secret_key, algorithm='HS256')  # [1:].replace('\'', "")
                            user.token = token
                            user.logged_in = True
                            user.last_login = datetime.today().strftime("%Y-%m-%d %H:%M")
                            user.save()
                        else:
                            raise serializers.ValidationError({"Message": "Invalid login Credentials", "token": ""})
                    # else:
                    #     raise serializers.ValidationError(
                    #         {"Message": "User Already Logged in.Logout First", "token": ""})
                else:
                    raise serializers.ValidationError({"Message": "User is Inactive", "token": ""})

            else:
                raise serializers.ValidationError({"Message": "Invalid login Credentials", "token": ""})

        except ObjectDoesNotExist:
            token = None
        return token


def check_roles(roleId):
    try:
        role = AndroidRoles.objects.get(roleid=roleId)
        if role.RoleType is not None:
            roleName = role.RoleType
        else:
            roleName = None
    except Exception as e:
        logging.getLogger(str("The Exception is: %s".join(e.args)).strip())
        roleName = None
    return roleName


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
                    password = encryptRawValues(data['password'])
                    print("Encrypted password", password)
                    email = data.get('email')
                    FirstName = data['firstname']
                    SecondName = data['lastname']
                    roleId = data['role']
                    print("RoleName is: ", check_roles(roleId))
                    if check_roles(roleId) is not None:
                        if check_roles(roleId) == "ADMIN":
                            user = AddUsersIntoDb().create_superuser(email=email,
                                                                     password=password,
                                                                     lastname=SecondName,
                                                                     firstname=FirstName, )
                        elif check_roles(data.get('RoleId')) == "STAFF":
                            user = AddUsersIntoDb().create_staffuser(email=email,
                                                                     password=password,
                                                                     firstname=FirstName,
                                                                     lastname=SecondName, )
                        else:
                            user = AddUsersIntoDb().create_normal_user(email=email,
                                                                       password=password,
                                                                       firstname=FirstName,
                                                                       lastname=SecondName)
                        entityResponse = {'FirstName': user.firstname,
                                          'LastName': user.lastname,
                                          'email': user.email,
                                          'Role': check_roles(roleId)}
                        return entityResponse
                    else:
                        raise serializers.ValidationError({"Message": "Insufficient priviledges"})


class ListAllUsers(serializers.ListSerializer, PageNumberPagination):
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

    @staticmethod
    def listUsers():
        user = UserModel.objects.all()
        if user is not None:
            return user
        else:
            return user or None

    def findByEmail(self, data):
        user = None
        try:
            user = UserModel.objects.get(email=data['email'])
            if user is not None:
                user = user
                return user
            else:
                user = None
                return user
        except UserModel.DoesNotExist:
            return user or None


class DecodeToken:
    @staticmethod
    def decodeToken(request):
        headers = authentication.get_authorization_header(request).split()
        if not headers or headers[0].lower() != b'token':
            loggedinuser = None
        elif len(headers) == 1:
            msg = 'Invalid token header. No credentials provided.'
            raise exceptions.AuthenticationFailed(msg)
        elif len(headers) > 2:
            msg = 'Invalid token header'
            raise exceptions.AuthenticationFailed(msg)
        else:
            try:
                token = headers[1]
                if token is None:
                    msg = 'Invalid token header'
                    raise exceptions.AuthenticationFailed(msg)
                else:
                    user_data = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
                    user_id = user_data['id']
                    # print("user_id",user_id)
                    username = user_data['subject']
                    role = user_data['roleId']
                    # print("token name:...." + str(role))
                    db_user = UserModel.objects.get(email__iexact=username)
                    db_token = db_user.token[1:].replace("\'", "")
                    passed_token = str(token)[2:].replace("\'", "")
                    if db_token == passed_token:
                        loggedinuser = dict()
                        loggedinuser['loggedinuser'] = loggedinuser
                        loggedinuser['roleId'] = role
                        loggedinuser['token'] = token
                    else:
                        loggedinuser = None
            except jwt.ExpiredSignature or jwt.DecodeError or jwt.InvalidTokenError:
                return HttpResponse({'Error': "Token is invalid"}, status="403")
            except UserModel.DoesNotExist:
                loggedinuser = None
        return loggedinuser
