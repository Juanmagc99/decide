from django.urls import include, path
from rest_framework.authtoken.views import obtain_auth_token

from .views import GetUserView, LogoutView, RegisterView

from django.contrib.auth.views import login, logout

urlpatterns = [
    path('login/', obtain_auth_token),
    path('logout/', LogoutView.as_view()),
    path('getuser/', GetUserView.as_view()),
    path('register/', RegisterView.as_view()),

    path('loginUser/', login, {'template_name': 'login.html'}, name='loginUser'),
    path('logoutUser/', logout, name="logoutUser"),
]
