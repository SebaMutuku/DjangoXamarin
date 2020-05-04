"""DjangoApp URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.11/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf.urls import url
from django.contrib import admin

from Android import views

app_name = 'Android'

urlpatterns = [
    url(r'^admin/', admin.site.urls),
    url(r'^api/users/login', views.Login.as_view(), name='Login'),
    url('api/users/register', views.Register.as_view(), name='Register'),
    url('api/users/listusers', views.FetchUsers.as_view(), name='ListUsers'),
    url('api/users/logout', views.Logout.as_view(), name='Logout'),
    url('api/users/findbymail', views.FindUserByEmail.as_view(), name='FindUsersByEmail'),
    url('api/users/googleApi', views.GoogleView.as_view(), name='GoogleApi'),

]
