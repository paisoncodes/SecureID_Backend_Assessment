from rest_framework import serializers
from .models import User
from rest_framework.validators import UniqueValidator
from config.utils import Utils


class RegisterUserSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(
        required=True, validators=[UniqueValidator(queryset=User.objects.all())]
    )
    full_name = serializers.CharField(max_length=255)
    password = serializers.CharField(
        write_only=True,
        required=True,
        validators=[Utils.validate_user_password],
        help_text="Password must be at least 6 characters and must contain at least one uppercase letter, one smaller letter, one digit, and one special character.",
    )
    password2 = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ("email", "full_name", "username", "password", "password2")
        extra_kwargs = {
            "password": {"write_only": True},
        }

    def validate(self, attrs):
        if attrs["password"] != attrs["password2"]:
            raise serializers.ValidationError(
                {"password": "Password fields didn't match."}
            )

        return attrs

    def create(self, validated_data):
        user = User.objects.create(
            email=validated_data["email"],
            first_name=validated_data["full_name"],
            username=validated_data["username"],
        )

        user.set_password(validated_data["password"])
        user.save()

        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True)


class TokenRefreshSerializer(serializers.Serializer):
    refresh = serializers.CharField(required=True)


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(
        write_only=True,
        required=True,
        validators=[Utils.validate_user_password],
        help_text="Password must be at least 6 characters and must contain at least one uppercase letter, one smaller letter, one digit, and one special character.",
    )
    confirm_password = serializers.CharField(required=True)

    def validate(self, attrs):
        if attrs["new_password"] != attrs["confirm_password"]:
            raise serializers.ValidationError(
                {"password": "Password fields didn't match."}
            )

        return attrs


class GenerateResetTokenSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True, validators=[Utils.confirm_email])


class ResetPasswordSerializer(serializers.Serializer):
    token = serializers.CharField(required=True)
    password = serializers.CharField(
        write_only=True,
        required=True,
        validators=[Utils.validate_user_password],
        help_text="Password must be at least 6 characters and must contain at least one uppercase letter, one smaller letter, one digit, and one special character.",
    )
    confirm_password = serializers.CharField(required=True)

    def validate(self, attrs):
        if attrs["password"] != attrs["confirm_password"]:
            raise serializers.ValidationError(
                {"password": "Password fields didn't match."}
            )

        return attrs
