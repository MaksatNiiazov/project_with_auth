from django.urls import path
from apps.users.api.v1.views import RegisterView, ActivateView, LogoutView, CustomTokenObtainPairView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='api_register'),
    path('activate/<uidb64>/<token>/', ActivateView.as_view(), name='api_activate'),
    path('login/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('logout/', LogoutView.as_view(), name='logout'),
]
