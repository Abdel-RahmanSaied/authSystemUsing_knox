from rest_framework import serializers
from rest_framework.routers import DefaultRouter
from django.urls import path, include
from .views import LoginView, LogoutView, LogoutAllView, UserViewSet, PasswordResetViewSet

# from .views import PasswordResetViewSet


router = DefaultRouter()
router.register(r'users', UserViewSet, basename='user')

router.register(r'password-reset', PasswordResetViewSet, basename='password-reset')


urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('logoutAll/', LogoutAllView.as_view(), name='logout-all'),

    # path('reset-password/', PasswordResetRequestView.as_view(), name='password_reset'),
    # path('reset-password/<str:uidb64>/<str:token>/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),

]

urlpatterns += router.urls
