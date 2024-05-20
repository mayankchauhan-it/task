from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.register_view, name='register_view'),
    path('login/', views.login_view, name='login_view'),
    path('profile/update/', views.profile_update_view, name='profile_update_view'),
    
    
    
    path('api/register/', views.register_user, name='register'),
    path('api/login/', views.login_user, name='login'),
    path('api/profile/update/', views.update_profile, name='update_profile'),
    
    path('logout/', views.logout_view, name='logout_view'),
    
    
    path('forgot-password/', views.forgot_password, name='forgot_password'),
    path('reset-password/<uidb64>/<token>/', views.reset_password, name='reset_password'),
]