from django.urls import path

from .views import (ChangeUserPassword, GenerateResetToken, RegisterUser,
                    ResetPassword, UserLogin)

urlpatterns = [
    path('register/', RegisterUser.as_view()),
    path('login/', UserLogin.as_view()),
    path('change-password/', ChangeUserPassword.as_view()),
    path('reset-password/', GenerateResetToken.as_view()),
    path('generate-reset-token/', GenerateResetToken.as_view())
]
