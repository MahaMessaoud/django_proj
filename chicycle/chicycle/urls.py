"""
URL configuration for chicycle project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from django.contrib.auth.views import LogoutView

# urlpatterns = [
#     path('admin/', admin.site.urls),
# ]
from django.contrib import admin
from django.urls import path
from users import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('login/', views.login_view, name='login'),
    path('superadmin_dashboard/', views.superadmin_dashboard, name='superadmin_dashboard'),
    path('admin_dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('user_dashboard/', views.user_dashboard, name='user_dashboard'),
    path('register/', views.register_view, name='register'),  # URL d'inscription
    path('logout/', LogoutView.as_view(), name='logout'),  # URL pour la déconnexion
  path('users/', views.get_all_users, name='get_all_users'),  # URL pour la gestion des utilisateurs
    path('users/update/<int:user_id>/', views.update_user, name='update_user'),  # URL pour mettre à jour un utilisateur
    path('users/ban/<int:user_id>/', views.ban_user, name='ban_user'),  # URL pour bannir un utilisateur
    path('users/unban/<int:user_id>/', views.unban_user, name='unban_user'),  # URL pour débannir un utilisateur
]
