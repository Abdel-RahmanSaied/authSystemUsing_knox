from django.shortcuts import render
from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.utils import timezone
from datetime import timedelta
from django.contrib.auth.tokens import default_token_generator

from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.serializers import DateTimeField
from rest_framework.settings import api_settings
from rest_framework.views import APIView
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.throttling import UserRateThrottle

from knox.auth import TokenAuthentication
from knox.models import AuthToken
from knox.settings import knox_settings
from knox.views import LoginView as KnoxLoginView

from .serializers import UserSerializer, AuthTokenSerializer, PasswordResetCreateSerializer, \
    PasswordResetConfirmSerializer

from .models import USER, PasswordReset, EmailVerification
from .permissions import UserPermission
from .emailSender import send_passwordreset_verification_mail, send_verification_mail
from .forms import AdvancedLoginForm

from django.contrib.auth import get_user_model
# print("get_user_model()", get_user_model())


import secrets
import urllib.parse



class LoginView(KnoxLoginView):
    authentication_classes = api_settings.DEFAULT_AUTHENTICATION_CLASSES
    permission_classes = (AllowAny,)
    form = AdvancedLoginForm
    # serializer_class = LoginSerializer
    serializer_class = AuthTokenSerializer

    def post(self, request, format=None):
        token_limit_per_user = self.get_token_limit_per_user()
        serializer = self.serializer_class(data=request.data)  # Use the LoginSerializer

        if serializer.is_valid():
            user = serializer.validated_data['user']

            if token_limit_per_user is not None:
                now = timezone.now()
                token = AuthToken.objects.filter(user=user, expiry__gt=now)
                # token = request.user.auth_token_set.filter(expiry__gt=now)
                if token.count() >= token_limit_per_user:
                    return Response(
                        {"error": "Maximum amount of tokens allowed per user exceeded."},
                        status=status.HTTP_403_FORBIDDEN
                    )

            print(request.META.get('HTTP_ACCEPT', ''))
            token_ttl = self.get_token_ttl()
            instance, token = AuthToken.objects.create(user, token_ttl)
            user_logged_in.send(sender=user.__class__, request=request, user=user)
            return Response({"token": token}, status=status.HTTP_201_CREATED)
        else:
            if 'text/html' in request.META.get('HTTP_ACCEPT', ''):
                return render(request, 'login.html', {'form': self.form(request.POST)})
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request, format=None):
        if 'text/html' in request.META.get('HTTP_ACCEPT', ''):  # Check if HTML response is requested
            form = self.form()
            return render(request, 'login.html', {'form': form})
        else:  # API request, return JSON response
            return Response({"Message": "Method not allowed"}, status=status.HTTP_405_METHOD_NOT_ALLOWED)


class LogoutView(APIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def post(self, request, format=None):
        request._auth.delete()
        user_logged_out.send(sender=request.user.__class__,
                             request=request, user=request.user)
        return Response(None, status=status.HTTP_204_NO_CONTENT)


class LogoutAllView(APIView):
    '''
    Log the user out of all sessions
    I.E. deletes all auth tokens for the user
    '''
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def post(self, request, format=None):
        request.user.auth_token_set.all().delete()
        user_logged_out.send(sender=request.user.__class__,
                             request=request, user=request.user)
        return Response(None, status=status.HTTP_204_NO_CONTENT)


class UserViewSet(viewsets.ModelViewSet):
    queryset = USER.objects.all()
    serializer_class = UserSerializer
    # permission_classes = [UserPermission]
    permission_classes = [AllowAny]
    search_fields = ('username', 'email', 'first_name', 'last_name', 'phone', 'job_tittle', 'department',
                     'organization', 'country',)
    filterset_fields = ('id', 'username', 'email', 'first_name', 'last_name', 'phone', 'job_tittle', 'department',
                        'organization', 'country',)
    ordering_fields = ('username', 'email', 'first_name', 'last_name', 'phone', 'job_tittle', 'department',
                       'organization', 'country',)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        account = serializer.save()

        # generate a token
        key = secrets.token_urlsafe(32)
        # Create a password reset instance
        emailVerification = EmailVerification.objects.create(user=account, key=key)

        # generate a reset link
        # verify_url = request.build_absolute_uri(f"/auth/users/{key}/verifyAccount/")
        verify_url = f"http://127.0.0.1:8000/auth/users/{urllib.parse.quote(key)}/verifyAccount/"

        # Send password reset email
        try:
            print(verify_url)
            send_verification_mail(account, verify_url, key)
        except (TypeError, ValueError, OverflowError) as e:
            print(e)
            # Handle email sending error here
            return Response({'error': 'Failed to send password reset email.'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


        # headers = self.get_success_headers(serializer.data)
        # return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=['get'],)
    def verifyAccount(self, request, pk=None, *args, **kwargs):

        try:
            key = EmailVerification.objects.get(key=pk)
        except EmailVerification.DoesNotExist:
            return Response({'error': 'Invalid or expired token.'}, status=status.HTTP_400_BAD_REQUEST)

        expiration_time = key.expire_at
        if timezone.now() > expiration_time:
            return Response({'error': 'Token has expired.'}, status=status.HTTP_400_BAD_REQUEST)

        user = key.user
        if not user.email_verified:
            if user.verify_account():
                key.delete()
                return Response({"detail": "Account verification Successfully"}, status=status.HTTP_200_OK)
            return Response({"error": "Failed to verify your account please try again"}, status=status.HTTP_400_BAD_REQUEST)
        return Response({"error": "Account Already verified"}, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetViewSet(viewsets.ModelViewSet):
    queryset = PasswordReset.objects.all()
    serializer_class = PasswordResetCreateSerializer
    permission_classes = [AllowAny]
    lookup_field = 'token'
    http_method_names = ['post']
    throttle_classes = [UserRateThrottle]

    def create(self, request, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']

        # generate a token
        token = secrets.token_urlsafe(32)
        # Create a password reset instance
        password_reset = PasswordReset.objects.create(user=user, token=token)

        # generate a reset link
        reset_link = request.build_absolute_uri(f"/auth/password-reset/{token}/confirm/")

        # Send password reset email
        try:
            send_passwordreset_verification_mail(user, reset_link, token)
        except (TypeError, ValueError, OverflowError) as e:
            print(e)
            # Handle email sending error here
            return Response({'error': 'Failed to send password reset email.'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({'message': 'Password reset email sent successfully.'}, status=status.HTTP_200_OK)

    @action(detail=True, methods=['post'])
    def confirm(self, request, token=None, **kwargs):
        try:
            password_reset = PasswordReset.objects.get(token=token)
        except PasswordReset.DoesNotExist:
            return Response({'error': 'Invalid or expired token.'}, status=status.HTTP_400_BAD_REQUEST)

        # Check if the token is still valid (e.g., not expired)
        # expiration_time = password_reset.created_at + timedelta(hours=1)
        expiration_time = password_reset.expire_at
        if timezone.now() > expiration_time:
            return Response({'error': 'Token has expired.'}, status=status.HTTP_400_BAD_REQUEST)

        # Handle password reset confirmation and set new password for the user
        serializer = PasswordResetConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        new_password = serializer.validated_data['new_password']

        # Set new password for the user
        user = password_reset.user
        user.set_password(new_password)
        user.save()

        # Delete all password reset instances for the user
        PasswordReset.objects.filter(user=user).delete()

        return Response({'message': 'Password reset successful.'}, status=status.HTTP_200_OK)
