from rest_framework import serializers
from rest_framework.response import Response
from rest_framework import status
from rest_framework import exceptions
from rest_framework.authentication import authenticate

class AuthCustomTokenSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length = 255)
    password = serializers.CharField(max_length = 255)

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        if email and password:
            # Check if user sent email
           user = authenticate(email=email,password=password)
           if user is None:
               msg = ('Invalid email or password')
               raise exceptions.AuthenticationFailed(msg)
        else:
            raise exceptions.ValidationError('Emal and Password are required')
        attrs['user'] = user
        return attrs


class SendmailSerializer(serializers.Serializer):
    subject = serializers.CharField(max_length = 255)
    message = serializers.CharField(max_length = 255)
    toUser = serializers.CharField(max_length = 255)

