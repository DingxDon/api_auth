from django.contrib import admin
from django.urls import path, include
from . import views
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView
)
from .views import PasswordChangeView, LogoutView, DeleteAccountView, Login_View, Register_view, Home_View



urlpatterns = [
    path('admin/', admin.site.urls),
    path("account/", include([
        path("signup/", views.SignUpView.as_view(), name="signup"),
        path("login/", views.LoginView.as_view(), name="login"),
        path('loginPage/', Login_View, name='LoginPage'),
        path('RegisterPage/', Register_view, name='RegisterPage'),
        path('HomePage/', Home_View, name='HomePage'),
        path("logout/", views.LogoutView.as_view(), name="logout"),
        path("password/change/", views.PasswordChangeView.as_view(), name="password_change"),
        path("delete-account/", views.DeleteAccountView.as_view(), name="delete_account"),
        path("jwt/", include([
            path("create/", TokenObtainPairView.as_view(), name="jwt_create"),
            path("refresh/", TokenRefreshView.as_view(), name="token_refresh"),
            path("verify/", TokenVerifyView.as_view(), name="token_verify"),
        ])),
    ])),
]