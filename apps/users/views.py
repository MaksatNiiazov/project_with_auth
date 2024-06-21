from django.contrib.auth import get_user_model
from django.contrib.auth.views import LoginView, LogoutView, PasswordResetView, PasswordResetConfirmView, \
    PasswordChangeView
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMessage
from django.http import HttpResponse
from django.shortcuts import render
from django.template.loader import render_to_string
from django.urls import reverse_lazy, reverse
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.views import View
from django.views.generic import CreateView, TemplateView

from apps.users.models import User
from .forms import SignupForm, LoginForm, CustomPasswordChangeForm
from .token import account_activation_token


class UserRegisterView(CreateView):
    model = User
    form_class = SignupForm
    template_name = 'registration/registration.html'
    success_url = reverse_lazy('registration:confirm')

    def form_valid(self, form):
        user = form.save(commit=False)
        user.is_active = False
        user.from_google = False
        user.save()

        current_site = get_current_site(self.request)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = account_activation_token.make_token(user)
        activation_link = reverse('activate', kwargs={'uidb64': uid, 'token': token})
        activation_link = self.request.build_absolute_uri(activation_link)

        mail_subject = 'Activation link has been sent to your email id'
        message = render_to_string('registration/acc_active_email.html', {
            'user': user,
            'activation_link': activation_link,
        })

        to_email = form.cleaned_data.get('email')
        email = EmailMessage(mail_subject, message, to=[to_email])
        email.content_subtype = "html"
        email.send()

        return render(self.request, "registration/confirm.html")


class ActivateView(View):
    def get(self, request, uidb64, token):
        User = get_user_model()
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None
        if user is not None and account_activation_token.check_token(user, token):
            user.is_active = True
            user.save()
            return render(request, "registration/thank_you_for_activation.html")
        else:
            return HttpResponse('Activation link is invalid!')


class CustomLoginView(LoginView):
    template_name = 'registration/login.html'
    form_class = LoginForm


class CustomLogoutView(LogoutView):
    next_page = reverse_lazy('users:login')


class CustomPasswordChangeView(PasswordChangeView):
    form_class = CustomPasswordChangeForm
    template_name = 'registration/password_change_form.html'
    success_url = reverse_lazy('password_change_done')


class PasswordChangeDoneView(TemplateView):
    template_name = 'registration/password_change_done.html'


class CustomPasswordResetView(PasswordResetView):
    email_template_name = 'registration/password_reset_email.html'
    subject_template_name = 'registration/password_reset_subject.txt'
    template_name = 'registration/password_reset_form.html'
    success_url = reverse_lazy('password_reset_done')


class CustomPasswordResetCompleteView(TemplateView):
    template_name = 'registration/password_reset_complete.html'


class CustomPasswordResetConfirmView(PasswordResetConfirmView):
    template_name = 'registration/password_reset_confirm.html'
    success_url = reverse_lazy('password_reset_complete')


class CustomPasswordResetDoneView(TemplateView):
    template_name = 'registration/password_reset_done.html'
