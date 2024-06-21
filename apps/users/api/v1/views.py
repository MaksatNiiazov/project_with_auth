from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from rest_framework import generics, status, serializers
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView

from apps.users.api.v1.serializers import RegisterSerializer, CustomTokenObtainPairSerializer
from apps.users.models import User
from apps.users.token import account_activation_token


class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = RegisterSerializer

    def perform_create(self, serializer):
        user = serializer.save()
        if user:
            mail_subject = 'Activation link has been sent to your email id'
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = account_activation_token.make_token(user)
            activation_link = reverse('api_activate', kwargs={'uidb64': uid, 'token': token})
            activation_link = self.request.build_absolute_uri(activation_link)

            message = render_to_string('registration/acc_active_email.html', {
                'user': user,
                'activation_link': activation_link,

            })
            to_email = serializer.validated_data.get('email')
            email = EmailMessage(mail_subject, message, to=[to_email])
            email.content_subtype = "html"
            email.send()
        else:
            raise serializers.ValidationError("Failed to create user")


class ActivateView(APIView):
    def get(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None
        if user is not None and account_activation_token.check_token(user, token):
            user.is_active = True
            user.save()
            return Response({'message': 'Thank you for your email confirmation. Now you can login your account.'},
                            status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Activation link is invalid!'}, status=status.HTTP_400_BAD_REQUEST)


class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer


class LogoutView(generics.GenericAPIView):
    def post(self, request, *args, **kwargs):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response(status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response(status=status.HTTP_400_BAD_REQUEST)
