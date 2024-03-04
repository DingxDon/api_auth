from django.contrib.auth import authenticate, login
from django.shortcuts import render, redirect
from rest_framework import generics, status, permissions
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView
from .tokens import create_jwt_pair
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt import token_blacklist
from django.contrib.auth import update_session_auth_hash
from rest_framework.permissions import IsAuthenticated
from .serializers import SignUpSerializer, LoginSerializer, PasswordChangeSerializer


class SignUpView(generics.GenericAPIView):
    serializer_class = SignUpSerializer
    permission_classes = []

    def post(self, request: Request):
        data = request.data

        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            response = {"message": "User Created Successfully",
                        "data": serializer.data}

            return Response(data=response, status=status.HTTP_201_CREATED)

        return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    permission_classes = []

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            tokens = serializer.save()
            response_data = {"message": "Login Successful",
                             "tokens": tokens}
            return Response(data=response_data,
                            status=status.HTTP_200_OK)
        else:
            return Response(data=serializer.errors,
                            status=status.HTTP_400_BAD_REQUEST)

    def get(self, request: Request):
        content = {"user": str(request.user),
                   "auth": str(request.auth)}
        return Response(data=content, status=status.HTTP_200_OK)


class PasswordChangeView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = PasswordChangeSerializer(data=request.data)
        if serializer.is_valid():
            user = request.user
            old_password = serializer.validated_data.get('old_password')
            new_password = serializer.validated_data.get('new_password')

            # Check if the old password is correct
            if not user.check_password(old_password):
                return Response({'detail': 'Incorrect old password.'},
                                status=status.HTTP_400_BAD_REQUEST)

            if new_password == old_password:
                return Response({
                    'detail': 'Passwords Must be Different'
                },
                    status=status.HTTP_400_BAD_REQUEST)
            # Set the new password and save the user
            user.set_password(new_password)
            user.save()

            # Issue a new JWT token
            refresh = RefreshToken.for_user(user)
            tokens = {"refresh": str(refresh), "access": str(
                refresh.access_token)}

            # Update the session authentication hash
            update_session_auth_hash(request, user)

            return Response({'detail': 'Password changed successfully.',
                            'tokens': tokens}, status=status.HTTP_200_OK)
        return Response(serializer.errors,
                        status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):
    permission_classes = (permissions.AllowAny,)
    authentication_classes = ()

    def post(self, request):
        refresh_token = request.data.get('refresh')
        if refresh_token:
            try:
                token = RefreshToken(refresh_token)
                token.blacklist()
                return Response({'message': 'Logged out successfully.'}, status=status.HTTP_200_OK)
            except token_blacklist.exceptions.BlacklistError:
                return Response({'error': 'Token is already blacklisted.'}, status=status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'error': 'No refresh token provided.'}, status=status.HTTP_400_BAD_REQUEST)


class DeleteAccountView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request):
        user = request.user
        user.delete()
        return Response(
            {
                "message": "Account has been Deleted!"
            },
            status=status.HTTP_204_NO_CONTENT
        )




def Login_View(request):
    return render(request, 'loginpage.html')


def Register_view(request):
    return render(request, 'register.html')


def Home_View(request):
    return render(request, 'homepage.html')

# password reset
# otp
# email conformation
