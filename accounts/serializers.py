from rest_framework import serializers
from rest_framework.validators import ValidationError, UniqueValidator
from .models import User
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken




class SignUpSerializer(serializers.ModelSerializer):

    email = serializers.EmailField(max_length=80, validators=[UniqueValidator(queryset=User.objects.all())])
    username = serializers.CharField(max_length=45)
    password = serializers.CharField(min_length=8, write_only=True)

    class Meta:
        model = User
        fields = ['email', 'username', 'password']

    def validate(self, attrs):
        email_exists = User.objects.filter(email=attrs['email']).exists()
        if email_exists:
            raise ValidationError("Email has already been used")
        return super().validate(attrs)

    def create(self, validated_data):
        password = validated_data.pop("password")
        user =  super().create(validated_data)
        user.set_password(password)
        user.save()
        #Token Implementation
        Token.objects.create(user=user)
        return user
    
class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()

    def validate(self, attrs):
        email = attrs.get("email")
        password = attrs.get("password")

        if email and password:
            user = authenticate(email=email, password=password)
            if not user:
                raise AuthenticationFailed("Invalid email or password.")
        else:
            raise AuthenticationFailed("Both email and password are required.")

        return super().validate(attrs)

    def create(self, validated_data):
        user = authenticate(
            email=validated_data.get("email"),
            password=validated_data.get("password")
        )
        refresh = RefreshToken.for_user(user)
        tokens = {"refresh": str(refresh), "access": str(refresh.access_token)}
        return tokens
    
    
class PasswordChangeSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True, min_length=12)
    confirm_password = serializers.CharField(required=True, min_length=12)  # Minimum length set to 12 characters

    def validate(self, attrs):
        new_password = attrs.get('new_password')
        confirm_password = attrs.get('confirm_password')

        if new_password != confirm_password:
            raise serializers.ValidationError("The new passwords do not match.")

        return attrs
    
class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()
    
    def validate_email(self, value):
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email Address Does not exist!")
        
    def save(self):
        email = self
        
class DeleteAccountSerializer(serializers.Serializer):
    confirmation = serializers.BooleanField(required=True)