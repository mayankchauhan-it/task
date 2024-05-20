from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from authentication.models import *
@login_required
def dashboard_view(request):
    return render(request, 'dashboard/index.html')


def user_profile(request):
    all_profile = Profile.objects.all()
    all_users = User.objects.all()
    user = request.user
    
    for i in all_users:
        print(i.username)
    
    context = {
        'user': user, 
        'all_profile': all_profile,
        'all_users': all_users,
        'segment' : 'user_list'
    }
    return render(request, 'dashboard/user_page.html', context = context)