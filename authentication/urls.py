from rest_framework import serializers
from rest_framework.routers import DefaultRouter
from django.urls import path, include
from .views import LoginView, LogoutView, LogoutAllView, UserViewSet

from .views import testRefresh


router = DefaultRouter()
router.register(r'users', UserViewSet, basename='user')

urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('logoutAll/', LogoutAllView.as_view(), name='logout-all'),
    path("testRefesh/", testRefresh.as_view(), name="testRefesh"),
]

urlpatterns += router.urls
