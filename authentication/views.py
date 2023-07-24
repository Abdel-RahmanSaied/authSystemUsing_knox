from django.shortcuts import render
from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.serializers import DateTimeField
from rest_framework.settings import api_settings
from rest_framework.views import APIView
from rest_framework import viewsets
from rest_framework.authtoken.serializers import AuthTokenSerializer

from knox.auth import TokenAuthentication
from knox.models import AuthToken
from knox.settings import knox_settings

# import login view from knox
from knox.views import LoginView as KnoxLoginView
from .serializers import LoginSerializer, UserSerializer, PasswordResetSerializer
from .models import USER, PasswordReset
from .permissions import UserPermission
from .emailSender import send_passwordreset_verification_mail

from django.contrib.auth import get_user_model
# print("get_user_model()", get_user_model())

from django.utils.crypto import get_random_string
from django.core.mail import send_mail
from datetime import timedelta
from django.utils import timezone

# forms
from .forms import AdvancedLoginForm


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


class PasswordResetViewSet(viewsets.ModelViewSet):
    queryset = PasswordReset.objects.all()
    serializer_class = PasswordResetSerializer
    permission_classes = [AllowAny]
    lookup_field = 'token'


    def create(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']

        try:
            user = USER.objects.get(email=email)
        except USER.DoesNotExist:
            return Response({'error': 'User with this email address does not exist.'}, status=status.HTTP_404_NOT_FOUND)

        # Create a password reset instance
        token = get_random_string(length=32)
        password_reset = PasswordReset.objects.create(user=user, token=token)

        # Send password reset email
        reset_link = request.build_absolute_uri(f"/auth/password-reset/{token}/")

        send_passwordreset_verification_mail(user, reset_link, token)

        return Response({'message': 'Password reset email sent.'}, status=status.HTTP_200_OK)

    def retrieve(self, request, token=None):
        try:
            password_reset = PasswordReset.objects.get(token=token)
        except PasswordReset.DoesNotExist:
            return Response({'error': 'Invalid or expired token.'}, status=status.HTTP_400_BAD_REQUEST)

        # Check if the token is still valid (e.g., not expired)
        expiration_time = password_reset.created_at + timedelta(hours=1)  # Token expires after 1 hour
        if timezone.now() > expiration_time:
            return Response({'error': 'Token has expired.'}, status=status.HTTP_400_BAD_REQUEST)

        # Handle password reset confirmation and set new password for the user

        return Response({'message': 'Password reset successful.'}, status=status.HTTP_200_OK)
