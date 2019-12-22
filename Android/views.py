# -*- coding: utf-8 -*-


from django.contrib.auth import logout
from rest_framework import status, views
from rest_framework.authentication import SessionAuthentication, BasicAuthentication, TokenAuthentication
from rest_framework.authtoken.models import Token
from rest_framework.decorators import parser_classes
from rest_framework.pagination import PageNumberPagination
from rest_framework.parsers import JSONParser
from rest_framework.permissions import AllowAny
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response
from rest_framework.views import APIView

from . import models
from .AndroidSerializer import LoginSerializer, RegisterSerializer, ListAllUsers


class Login(APIView):
    querySet = models.Users.objects.all()
    renderer_classes = (JSONRenderer,)
    serializer_class = LoginSerializer
    permission_classes = (AllowAny,)
    authentication_classes = (SessionAuthentication, BasicAuthentication)
    parser_classes(JSONParser, )
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        if serializer.is_valid():
            user = serializer.loginUser(request.data)
            print (str(user))
            if user is not None:
                token, created = Token.objects.get_or_create(user=user)
                if token is not None:
                    response = {"Message": "Successfully Logged In ", "token": token.key}
                    return Response(response, status=status.HTTP_200_OK)
                else:
                    response = {{"Message": "Invalid Login Credentials", "token": None}}
                    return Response(response, status=status.HTTP_200_OK)
            else:
                response = {"Message": "Invalid Login Credentials", "token": None}
                return Response(response, status=status.HTTP_200_OK)
        else:
            response = serializer.errors
            return Response(response)


class Register(views.APIView):
    permission_classes = (AllowAny,)
    querySet = models.Users.objects.all()
    serializer_class = RegisterSerializer
    parser_classes(JSONParser, )
    pagination_class = PageNumberPagination

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.addUser(request.data)
            if user:
                return Response({"User": serializer.data,
                                 "Message": "Successfully created user " "[" + request.data.get('Username') + "]"},
                                status=status.HTTP_200_OK)
            else:
                return Response({"Invalid login credentials"},
                                status=status.HTTP_401_UNAUTHORIZED)

        else:
            return Response(serializer.errors, status.HTTP_401_UNAUTHORIZED)


class Logout(views.APIView):
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        user = logout(request)
        if user:
            return Response({"Message": "Successfully logged out " + request.user.username},
                            status=status.HTTP_200_OK)
        else:
            return Response({"Message": "Error Occurred while logging out"}, status=status.HTTP_401_UNAUTHORIZED)


class FetchUsers(views.APIView):
    permission_classes = (AllowAny,)
    querySet = models.Users.objects.all()
    serializer_class = ListAllUsers
    parser_classes(JSONParser, )
    pagination_class = PageNumberPagination

    def get(self, request):
        query = self.querySet
        serializer = self.serializer_class(data=request.data)
        data = serializer.listUsers(request.data)
        if serializer.is_valid():
            if data:
                if data is not None:
                    return Response({"Users": data, "Message": "Successfully fetched Data"}, status=status.HTTP_200_OK)
                else:
                    return Response({"Users": data, "Message": " Data not found"}, status=status.HTTP_404_NOT_FOUND)
            else:
                return Response("Not Found", status.HTTP_401_UNAUTHORIZED)

        else:
            return Response(serializer.errors, status.HTTP_401_UNAUTHORIZED)


class FindUserByEmail(views.APIView):
    permission_classes = (AllowAny,)
    querySet = models.Users.objects.all()
    serializer_class = ListAllUsers
    parser_classes(JSONParser, )
    pagination_class = PageNumberPagination

    def get(self, request):
        serializer = self.serializer_class(data=request.data)
        data = serializer.findByEmail(request.data)
        if serializer.is_valid():
            if data:
                if data is not None:
                    return Response({"Users": data, "Message": "Successfully fetched Data"},
                                    status=status.HTTP_200_OK)
                else:
                    return Response({"Users": data, "Message": " Data not found"}, status=status.HTTP_200_OK)
            else:
                return Response({"Message": "User not found"}, status.HTTP_200_OK)

        else:
            return Response(serializer.errors, status.HTTP_400_BAD_REQUEST)
