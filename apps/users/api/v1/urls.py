from django.urls import path
from apps.users.api.v1.views import RegisterAPIView, ActivateAPIView, CustomTokenObtainPairAPIView, LogoutAPIView, \
    CustomPasswordResetConfirmAPIView, CustomPasswordResetAPIView, CustomPasswordChangeAPIView

urlpatterns = [
    path('register/', RegisterAPIView.as_view(), name='api_register'),
    path('activate/<uidb64>/<token>/', ActivateAPIView.as_view(), name='api_activate'),
    path('login/', CustomTokenObtainPairAPIView.as_view(), name='token_obtain_pair'),
    path('logout/', LogoutAPIView.as_view(), name='logout'),
    path('password_reset/', CustomPasswordResetAPIView.as_view(), name='api_password_reset'),
    path('password_reset_confirm/<uidb64>/<token>/', CustomPasswordResetConfirmAPIView.as_view(),
         name='api_password_reset_confirm'),
    path('change_password/', CustomPasswordChangeAPIView.as_view(), name='api_change_password'),
]
