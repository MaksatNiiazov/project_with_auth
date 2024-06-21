from django.urls import path, include
from .views import UserRegisterView, ActivateView, CustomLoginView, CustomLogoutView, CustomPasswordResetView, \
    CustomPasswordResetConfirmView

urlpatterns = [
    path('api/v1/', include('apps.users.api.v1.urls')),
    path('register/', UserRegisterView.as_view(), name='register'),
    path('activate/<uidb64>/<token>/', ActivateView.as_view(), name='activate'),
    path('login/', CustomLoginView.as_view(), name='login'),
    path('logout/', CustomLogoutView.as_view(), name='logout'),
    path('password_reset/', CustomPasswordResetView.as_view(), name='password_reset'),
    path('reset/<uidb64>/<token>/', CustomPasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('password_reset/done/', PasswordResetDoneView.as_view(), name='password_reset_done'),
    path('reset/done/', PasswordResetCompleteView.as_view(), name='password_reset_complete'),
]