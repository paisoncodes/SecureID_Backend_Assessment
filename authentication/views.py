from config.utils import Utils
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import User
from .serializers import (
    ChangePasswordSerializer,
    LoginSerializer,
    RegisterUserSerializer,
    TokenRefreshSerializer,
    ResetPasswordSerializer,
    GenerateResetTokenSerializer,
)

# Create your views here.


class RegisterUser(APIView):
    serializer_class = RegisterUserSerializer
    queryset = User.objects.all()

    def post(self, request):
        serializer = RegisterUserSerializer(data=request.POST)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"code": 201, "status": "Success", "message": serializer.data},
                status=status.HTTP_201_CREATED,
            )
        else:
            return Response(
                {"code": 400, "status": "Failed", "message": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST,
            )


class UserLogin(APIView):
    serializer_class = LoginSerializer

    def post(self, request):
        if "email" not in request.data.keys() or "password" not in request.data.keys():
            return Response(
                {
                    "code": 400,
                    "status": "Failed",
                    "message": "Please enter your email address and password.",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        else:
            response = Utils.create_token(
                email=request.POST["email"], password=request.POST["password"]
            )
            if "error" in response.keys():
                return Response(
                    {"code": 400, "status": "Failed", "message": response},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            else:
                return Response(
                    {"code": 200, "status": "Success", "message": response},
                    status=status.HTTP_200_OK,
                )


class RefreshToken(APIView):
    serializer_class = TokenRefreshSerializer

    def post(self, request):
        if "refresh" not in request.POST:
            return Response(
                {
                    "code": 400,
                    "status": "Failed",
                    "message": "Refresh token not provided",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        else:
            response = Utils.refresh_token(refresh=request.data.get("refresh"))
            if "error" in response.keys():
                return Response(
                    {"code": 401, "status": "Failed", "message": response},
                    status=status.HTTP_401_UNAUTHORIZED,
                )
            else:
                return Response(
                    {"code": 200, "status": "Success", "message": response},
                    status=status.HTTP_200_OK,
                )


class ChangeUserPassword(APIView):
    serializer_class = ChangePasswordSerializer

    def post(self, request):
        if (
            "old_password" not in request.data.keys()
            or "new_password" not in request.data.keys()
            or "confirm_password" not in request.data.keys()
        ):
            return Response(
                {
                    "code": 400,
                    "status": "Failed",
                    "message": "Please fill all the fields.",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        else:
            serializer = ChangePasswordSerializer(data=request.data)
            if serializer.is_valid():
                response = Utils.change_password(
                    email=request.user.email,
                    old_password=request.data.get("old_password"),
                    new_password=request.data.get("new_password"),
                )
                if "error" in response.keys():
                    return Response(
                        {"code": 400, "status": "Failed", "message": response},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
                else:
                    return Response(
                        {"code": 200, "status": "Success", "message": response},
                        status=status.HTTP_200_OK,
                    )
            else:
                return Response(
                    {"code": 400, "status": "Failed", "message": serializer.errors},
                    status=status.HTTP_400_BAD_REQUEST,
                )


class GenerateResetToken(APIView):
    serializer_class = GenerateResetTokenSerializer

    def post(self, request):
        serializer = GenerateResetTokenSerializer(data=request.POST)

        if serializer.is_valid():
            reset_token = Utils.generate_reset_token(email=request.POST.get("email"))
            return Response(
                {"code": 200, "status": "Success", "message": reset_token},
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                {"code": 400, "status": "Failed", "message": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST,
            )


class ResetPassword(APIView):
    serializer_class = ResetPasswordSerializer

    def post(self, request):
        get_user_response = Utils.get_token_user(token=request.POST.get("token"))
        if "error" in get_user_response.keys():
            return Response(
                {"code": 400, "status": "Failed", "message": get_user_response},
                status=status.HTTP_400_BAD_REQUEST,
            )
        else:
            user = get_user_response["user"]
            change_password_response = Utils.reset_password(
                email=user.email, password=request.POST.get("password")
            )
            return Response(
                {"code": 200, "status": "Success", "message": change_password_response},
                status=status.HTTP_200_OK,
            )
