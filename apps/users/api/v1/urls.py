from django.urls import path
from apps.users.api.v1.views import RegisterView, ActivateView, LogoutView, CustomTokenObtainPairView, \
    PasswordResetView, PasswordResetConfirmView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='api_register'),
    path('activate/<uidb64>/<token>/', ActivateView.as_view(), name='api_activate'),
    path('login/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('api/v1/password_reset/', PasswordResetView.as_view(), name='password_reset'),
    path('api/v1/password_reset_confirm/<uidb64>/<token>/', PasswordResetConfirmView.as_view(),
         name='password_reset_confirm'),
    path('api/v1/change_password/', ChangePasswordView.as_view(), name='change_password'),

]
