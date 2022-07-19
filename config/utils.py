import string
from django.conf import settings
from django.contrib.auth import authenticate
from django.core.exceptions import ValidationError
import jwt
from rest_framework_simplejwt.tokens import RefreshToken

from authentication.models import User

allowed_characters = set(string.ascii_letters + string.digits + string.punctuation)
class Utils:

    @staticmethod
    def validate_user_password(password):
        if (len(password) < 6):
            raise ValidationError("Password is too short")
        if any(pass_char not in allowed_characters for pass_char in password):
            raise ValidationError("Password contains illegal characters")

        if not any(pass_char.isdigit() for pass_char in password):
            raise ValidationError("Password must have at least one number")

        if not any(pass_char.isupper() for pass_char in password):
            raise ValidationError("Password must have at least one uppercase letter")

        if not any(pass_char.islower() for pass_char in password):
            raise ValidationError("Password must have at least one lowercase letter")

        if not any(pass_char in string.punctuation for pass_char in password):
            raise ValidationError("Password must have at least one special character")

        return True
    
    @staticmethod
    def create_token(email:str, password:str) -> dict:
        user = authenticate(email=email, password=password)
        if user:
            refresh = RefreshToken.for_user(user)
            return {
                'access': str(refresh.access_token),
                'refresh': str(refresh)
            }
        else:
            return {
                "error": "Invalid login details"
            }

    @staticmethod
    def generate_reset_token(email:str) -> dict:
        user = User.objects.get(email=email)
        reset_token = RefreshToken.for_user(user)
        return {
            'token': str(reset_token.access_token)
        }

    @staticmethod
    def refresh_token(refresh:str) -> dict:
        try:
            payload = jwt.decode(
                refresh, settings.SECRET_KEY, algorithms=["HS256"])
            user = User.objects.get(id=payload["user_id"])
            token = RefreshToken.for_user(user)
            return {
                'access': str(token.access_token)
            }
        except jwt.ExpiredSignatureError:
            return {"error": "Token expired"}

        except jwt.exceptions.DecodeError:
            return {"error": "Invalid token"}
    
    @staticmethod
    def get_token_user(token:str) -> dict:
        try:
            payload = jwt.decode(
                token, settings.SECRET_KEY, algorithms=["HS256"])
            user = User.objects.get(id=payload["user_id"])
            return {
                'user': user
            }
        except jwt.ExpiredSignatureError:
            return {"error": "Token expired"}

        except jwt.exceptions.DecodeError:
            return {"error": "Invalid token"}

    
    @staticmethod
    def change_password(email:str, old_password:str, new_password:str) -> dict:
        
        user = authenticate(email=email, password=old_password)
        if user:
            user.set_password(new_password)
            user.save()
            return {
                "message": "Password changed successfully"
            }
        else:
            return {
                "error": "Invalid password"
            }

    @staticmethod
    def reset_password(email:str, password:str) -> dict:
        user = User.objects.get(email=email)
        user.set_password(password)
        user.save()
        return {
            "message": "Password reset successful"
        }
    
    @staticmethod
    def confirm_email(email:str) -> bool:
        if not User.objects.filter(email=email).exists:
            raise ValidationError("Invalid email address")
        else:
            return True