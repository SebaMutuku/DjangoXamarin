import json

import requests
from rest_framework import serializers
# from Android.models import CredentialsModel
from rest_framework.utils import json

from Android.models import AndroidGooglemodel
from DjangoXamarin import settings


def getUserDetailsFromGoogle(request_data):
    payload = {'access_token': request_data.get('token'),
               'Expiry_time': request_data.get('expires_in'),
               'email': request_data.get('email')}
    scope = settings.GOOGLE_SCOPE
    client_id = settings.GOOGLE_API_CLIENT_ID
    secret_key = settings.GOOGLE_SECRET_KEY
    headers = {'Authorization': 'Bearer google '}
    try:
        google_response = requests.get(url=scope, params=payload)
        data = json.load(google_response.text)
        print("Response fromm google", data)
        if data.status_code == 200:
            try:
                google_user_data = AndroidGooglemodel.objects.create(Username=data.access_token,
                                                                     access_token=data.access_token,
                                                                     email=data.email, Expiry_time=data.expires_in)
                google_user_data.save()
                # token = RefreshToken.for_user(google_user_data)
                response = {'username': data.username,
                            'Token': str(data.access_token),
                            'refresh_token': str("token")}
                return response

            except Exception as e:
                raise serializers.ValidationError("The error is:", e)
        else:
            print("Invalid token")

    except Exception as exception:
        pass


class ExternalAPIs(serializers.Serializer):

    def getUserDetailsFromFacebook(self, data):
        pass

    def getUserDetailsFromGoogle(self, data):
        pass
