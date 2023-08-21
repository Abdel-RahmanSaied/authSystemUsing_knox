from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _
from .validators import ValidationError
from .generators import generate_verifyAccount_url
from .emailSender import send_verification_mail
from .models import PasswordReset, EmailVerification
from django.contrib.auth.password_validation import validate_password

USER = get_user_model()


class AuthTokenSerializer(serializers.Serializer):
    username = serializers.CharField(
        label=_("Username"),
        write_only=True
    )
    password = serializers.CharField(
        label=_("Password"),
        style={'input_type': 'password'},
        trim_whitespace=False,
        write_only=True
    )
    token = serializers.CharField(
        label=_("Token"),
        read_only=True
    )

    def validate(self, attrs):
        username = attrs.get('username')
        password = attrs.get('password')

        if username and password:
            user = authenticate(request=self.context.get('request'),
                                username=username, password=password)

            # The authenticate call simply returns None for is_active=False
            # users. (Assuming the default ModelBackend authentication
            # backend.)
            if not user:
                msg = _('Unable to log in with provided credentials.')
                raise ValidationError(msg, code='authorization')
        else:
            msg = _('Must include "username" and "password".')
            raise ValidationError(msg, code='authorization')

        attrs['user'] = user
        return attrs


class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=False)

    class Meta:
        model = USER
        fields = ('id', 'username', 'email', 'first_name', 'last_name', 'profile_picture',
                  'phone', 'job_tittle', 'department', 'organization', 'country', 'email_verified',
                  'password', 'date_joined', 'last_login')
        read_only_fields = ('id', 'date_joined', 'last_login', 'email_verified')

        extra_kwargs = {
            'password': {'write_only': True},
            'email': {'required': True},
            'username': {'required': True}
        }

    def validate_password(self, value):
        validate_password(value)
        return value



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

    def create(self, validated_data):
        user = USER.objects.create_user(**validated_data)
        # user = USER(**validated_data)
        url, key = generate_verifyAccount_url(request=self.context.get('request'))
        email_sent = send_verification_mail(user, url, key)
        if email_sent:
            EmailVerification.objects.create(user=user, key=key)
        return user


class PasswordResetCreateSerializer(serializers.Serializer):
    email = serializers.EmailField(write_only=True)

    class Meta:
        fields = ('email',)

    def validate(self, attrs):
        email = attrs.get('email')
        try:
            user = USER.objects.get(email=email)
        except USER.DoesNotExist:
            raise serializers.ValidationError({'email': 'User with this email address does not exist.'})
        attrs['user'] = user
        return attrs


class PasswordResetConfirmSerializer(serializers.Serializer):
    new_password = serializers.CharField(write_only=True, style={'input_type': 'password'})
    confirm_password = serializers.CharField(write_only=True, style={'input_type': 'password'})

    def validate(self, attrs):
        new_password = attrs.get('new_password')
        confirm_password = attrs.get('confirm_password')

        if new_password != confirm_password:
            raise serializers.ValidationError({'confirm_password': 'Passwords do not match.'})

        return attrs

    def validate_new_password(self, value):
        validate_password(value)
        return value

class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True, style={'input_type': 'password'})
    new_password = serializers.CharField(write_only=True, style={'input_type': 'password'})
    confirm_password = serializers.CharField(write_only=True, style={'input_type': 'password'})

    def validate(self, attrs):
        old_password = attrs.get('old_password')
        new_password = attrs.get('new_password')
        confirm_password = attrs.get('confirm_password')

        if new_password != confirm_password:
            raise serializers.ValidationError({'confirm_password': 'Passwords do not match.'})

        return attrs

    def validate_new_password(self, value):
        validate_password(value)
        return value

    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            # raise serializers.ValidationError({'old_password': 'Old password is incorrect.'})
            raise ValidationError({'old_password': 'Old password is incorrect.'})
        return value
