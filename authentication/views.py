from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.serializers import DateTimeField
from rest_framework.settings import api_settings
from rest_framework.views import APIView
from rest_framework import viewsets

from knox.auth import TokenAuthentication
from knox.models import AuthToken
from knox.settings import knox_settings

# import login view from knox
from knox.views import LoginView as KnoxLoginView
from .serializers import LoginSerializer
from .models import USER
from .permissions import UserPermission

from django.contrib.auth import get_user_model
# print("get_user_model()", get_user_model())

from knox.serializers import UserSerializer


class LoginView(KnoxLoginView):
    authentication_classes = api_settings.DEFAULT_AUTHENTICATION_CLASSES
    permission_classes = (AllowAny,)

    def post(self, request, format=None):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data['user']
        token_ttl = self.get_token_ttl()
        instance, token = AuthToken.objects.create(user, token_ttl)
        user_logged_in.send(sender=user.__class__, request=request, user=user)

        return Response({"token": token}, status=status.HTTP_201_CREATED,)


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

class UserRegisterView(viewsets.ModelViewSet):
    queryset = USER.objects.all()
    serializer_class = UserSerializer
    permission_classes = [UserPermission]
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

