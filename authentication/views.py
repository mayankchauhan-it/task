from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view
from .serializers import UserSerializer, ProfileSerializer, UserLoginSerializer
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from .models import Profile
from django.contrib.auth import logout
from rest_framework_simplejwt.tokens import AccessToken
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.shortcuts import reverse
from django.core.mail import send_mail
from datetime import datetime
from django.views.decorators.csrf import csrf_exempt
from django.utils.encoding import force_str



@api_view(['POST'])
def register_user(request):
    serializer = UserSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        
        try:
            profile = Profile.objects.get(user=user)  # noqa: F841
        except Profile.DoesNotExist:
            Profile.objects.create(user=user)
        
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
def login_user(request):
    serializer = UserLoginSerializer(data=request.data)
    if serializer.is_valid():
        username = serializer.validated_data['username']
        password = serializer.validated_data['password']
        user = authenticate(request, username=username, password=password)
        if user:
            login(request, user)
            access_token = AccessToken.for_user(user)
            return Response({"message": "Logged In", "token": str(access_token)}, status=status.HTTP_200_OK)
        else:
            return Response({"message": "Invalid details"}, status=status.HTTP_401_UNAUTHORIZED)
    else:
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def update_profile(request):
    user_profile, created = Profile.objects.get_or_create(user=request.user)
    
    request_data = request.data.copy()
    request_data['user'] = request.user.id
    
    serializer = ProfileSerializer(user_profile, data=request_data)
    
    if serializer.is_valid():
        serializer.save()
        return redirect('profile_update_view')
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


def register_view(request):
    if request.method == 'POST':
        response = register_user(request)
        if response.status_code == status.HTTP_201_CREATED:
            return redirect('login_view')
        return render(request, 'authentication/registrations.html', {'errors': response.data})
    return render(request, 'authentication/registrations.html')

def login_view(request):
    if request.method == 'POST':
        response = login_user(request)
        if response.status_code == status.HTTP_200_OK:
            if request.user.is_superuser:
                # Redirect superusers to /admin/
                return redirect('/admin/')
            else:
                # Redirect regular users to /user/
                return redirect('/dashboard/')
        return render(request, 'authentication/login.html', {'errors': response.data})
    return render(request, 'authentication/login.html')

@login_required
def profile_update_view(request):
    
    user_instanse = request.user
    
    try:
        profile_data = Profile.objects.get(user=user_instanse)
    except Profile.DoesNotExist:
        profile_data = Profile.objects.create(user=user_instanse)
    
    if request.method == 'POST':
        response = update_profile(request)
        if response.status_code == status.HTTP_200_OK:
            return render(request, 'authentication/profile_update.html', {'success': 'Profile updated'})
        return render(request, 'profile_update.html', {'errors': response.data})
    
    
    return render(request, 'authentication/profile_update.html', {'profile_data' : profile_data})


def logout_view(request):
    logout(request)
    return redirect('login_view')


# Forget Password Functionality
@api_view(['POST'])
@csrf_exempt
def forgot_password(request):
    email = request.data.get('email')
    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response({"error": "user not found"}, status=status.HTTP_404_NOT_FOUND)
    
    uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
    token = default_token_generator.make_token(user)
    reset_url = request.build_absolute_uri(reverse('reset_password', kwargs={'uidb64': uidb64, 'token': token}))
    
    subject = 'Reset Your Password'
    message = f"Click the link to reset password: {reset_url}"
    send_mail(subject, message, 'mayankchauhan.it@gmail.com', [email])
    
    return Response({"message": "Password reset link sent"}, status=status.HTTP_200_OK)

@api_view(['POST'])
def reset_password(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    
    if user is not None and default_token_generator.check_token(user, token):
        if datetime.now() > user.profile.password_reset_expiry:
            return Response({"error": "link  expired"}, status=status.HTTP_400_BAD_REQUEST)
        
        new_password = request.data.get('new_password')
        user.set_password(new_password)
        user.save()
        
        return Response({"message": "Password rested"}, status=status.HTTP_200_OK)
    
    return Response({"error": "Invalid reset link"}, status=status.HTTP_400_BAD_REQUEST)