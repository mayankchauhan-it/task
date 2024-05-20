from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard_view, name='dashboard_view'),
    path('user_profiles', views.user_profile, name='user_profiles'),
]