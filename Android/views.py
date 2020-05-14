# -*- coding: utf-8 -*-

from django.contrib.auth import logout
from rest_framework import status, views
from rest_framework.authentication import SessionAuthentication, BasicAuthentication, TokenAuthentication
from rest_framework.decorators import parser_classes
from rest_framework.pagination import PageNumberPagination
from rest_framework.parsers import JSONParser
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response
from rest_framework.views import APIView

from Android.serializers.AndroidSerializer import LoginSerializer, RegisterSerializer, ListAllUsers, DecodeToken
from . import models
from .serializers import OAuth2Serializer


class Login(APIView):
    querySet = models.Users.objects.all()
    renderer_classes = (JSONRenderer,)
    serializer_class = LoginSerializer
    permission_classes = (AllowAny,)
    authentication_classes = (SessionAuthentication, BasicAuthentication)
    parser_classes(JSONParser, )

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        if serializer.is_valid():
            token = serializer.checkLoginCredentials(request.data)
            if token is not None:
                response = {"Message": "Successfully Logged In ", "token": token}
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
        loggedinuser = DecodeToken().decodeToken(request)
        print(loggedinuser['roleId'])
        if loggedinuser is not None:
            roleId = loggedinuser['roleId']
            if roleId == 1 or roleId == 2:
                serializer = self.serializer_class(data=request.data)
                if serializer.is_valid(raise_exception=True):
                    user = serializer.addUser(request.data)
                    if user:
                        return Response({"User": serializer.data,
                                         "Message": "Successfully created user " "[" + request.data.get('email') + "]"},
                                        status=status.HTTP_200_OK)
                    else:
                        return Response({"Invalid login credentials"},
                                        status=status.HTTP_401_UNAUTHORIZED)

                else:
                    return Response(serializer.errors, status.HTTP_401_UNAUTHORIZED)
            else:
                return Response({"Message": "Insufficent privileges"},
                                status=status.HTTP_406_NOT_ACCEPTABLE)

        else:
            return Response({"Message": "Invalid Token"}, status=status.HTTP_401_UNAUTHORIZED)


class Logout(views.APIView):
    authentication_classes = (TokenAuthentication,)

    def post(self, request):
        user = logout(request=request)
        if user is None:
            return Response({"Message": "Successfully logged out "},
                            status=status.HTTP_200_OK)
        else:
            return Response({"Message": "Error Occurred while logging out"}, status=status.HTTP_401_UNAUTHORIZED)


class FetchUsers(views.APIView):
    serializer_class = ListAllUsers

    permission_classes = (IsAuthenticated,)

    def get(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            data = serializer.listUsers()
            # data = {"Data 1": "1", "Data 2": "2", "Data 3": "3", "Data 4": "4"}
            data = models.Users.objects.get(email=request.data['email'])
        return Response({"Payload": serializer.data, "Message": "Successful"}, status=status.HTTP_200_OK)


class FindUserByEmail(views.APIView):
    permission_classes = (IsAuthenticated,)
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
                    return Response({"Payload": data, "Message": "Successfully fetched Data"},
                                    status=status.HTTP_200_OK)
                else:
                    return Response({"Payload": data, "Message": " Data not found"}, status=status.HTTP_200_OK)
            else:
                return Response({"Message": "User not found"}, status.HTTP_200_OK)

        else:
            return Response(serializer.errors, status.HTTP_400_BAD_REQUEST)


class GoogleView(views.APIView):
    serializer_class = OAuth2Serializer.ExternalAPIs

    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            data = serializer.getUserDetailsFromGoogle(request.data)
            if data:
                return Response({"Payload": data, "Message": "Success"}, status=status.HTTP_200_OK)
            else:
                return Response({"Message": "Invalid grant-type"}, status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status.HTTP_400_BAD_REQUEST)


class FacebookView(views.APIView):
    serializer_class = OAuth2Serializer.ExternalAPIs

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            data = serializer.getUserDetailsFromFacebook(request.data)
            if data:
                return Response({"Payload": data, "Message": "Success"}, status=status.HTTP_200_OK)
            else:
                return Response({"Message": "Invalid grant-type"}, status.HTTP_401_UNAUTHORIZED)
        else:
            return Response(serializer.errors, status.HTTP_400_BAD_REQUEST)
