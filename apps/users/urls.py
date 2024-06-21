from django.urls import path, include
from .views import UserRegisterView, ActivateView, CustomLoginView, CustomLogoutView

urlpatterns = [
    path('api/v1/', include('apps.users.api.v1.urls')),
    path('register/', UserRegisterView.as_view(), name='register'),
    path('activate/<uidb64>/<token>/', ActivateView.as_view(), name='activate'),
    path('login/', CustomLoginView.as_view(), name='login'),
    path('logout/', CustomLogoutView.as_view(), name='logout'),

]
