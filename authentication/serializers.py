from rest_framework import serializers
from django.contrib.auth import authenticate
# from .backends import EmailAuthBackend
from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _
from .validators import ValidationError

USER = get_user_model()

from rest_framework.authtoken.serializers import AuthTokenSerializer


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(required=False, allow_blank=True)
    email = serializers.EmailField(required=False, allow_blank=True)
    password = serializers.CharField(style={'input_type': 'password'})

    def validate(self, data):
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')

        if not username and not email:
            raise serializers.ValidationError(_('Username or email is required.'))

        print(username, email, password)
        # Authenticate user with provided username/email and password
        user = authenticate(username=username, email=email, password=password)
        if user is None:
            raise ValidationError(_('Invalid credentials.'))
        data['user'] = user
        print(data)

        return data

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = USER
        fields = ('id', 'username', 'email', 'first_name', 'last_name', 'date_joined', 'last_login')
        read_only_fields = ('id', 'date_joined', 'last_login')

        read_only_fields = ('id', 'date_joined',)
        extra_kwargs = {
            'password': {'write_only': True},
            'email': {'required': True},
            'username': {'required': True}
        }

    def validate_password(self, value):
        validate_password(value)
        return value

    def create(self, validated_data):
        user = USER.objects.create_user(**validated_data)
        return user

    def update(self, instance, validated_data):
        # Create a dictionary to store the updated fields
        updated_fields = {}

        for field, value in validated_data.items():
            # Check if the field value has changed
            if getattr(instance, field) != value:
                updated_fields[field] = value

        if not updated_fields:
            raise serializers.ValidationError({"detail": "No data updated!"})

        validated_data.pop('password', None)
        user = super().update(instance, validated_data)
        return user