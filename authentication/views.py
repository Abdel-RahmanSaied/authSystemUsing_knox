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
from .serializers import LoginSerializer, UserSerializer
from .models import USER
from .permissions import UserPermission

from django.contrib.auth import get_user_model
# print("get_user_model()", get_user_model())

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

    # def create(self, request, *args, **kwargs):
    #     serializer = self.get_serializer(data=request.data)
    #     serializer.is_valid(raise_exception=True)
    #     user = serializer.save()
    #     headers = self.get_success_headers(serializer.data)
    #     token = Token.objects.get(user=user)
    #     data = serializer.data
    #     data['token'] = token.key
    #     return Response(data, status=status.HTTP_201_CREATED, headers=headers)


class testRefresh(APIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def get(self, request, format=None):
        return Response({"Message": "Token is valid"}, status=status.HTTP_200_OK)
