from django.urls import path
from .views import  logout, HandleLogin, JSONWebTokenAuth, sendMail
from . import  views

urlpatterns = [
    path('login', HandleLogin.as_view(), name = 'login'),
    path('logout',logout, name='logout'),
    path('auth/login', JSONWebTokenAuth.as_view(), name = 'authenticate'),
    path('auth/mail', views.sendMail )

]
