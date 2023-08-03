from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.conf import settings


def send_congratulations_email(user):
    subject = 'Congratulations on signing up!'
    template_name = 'congratulations_email.html'
    context = {'user': user}
    html_message = render_to_string(template_name, context)
    text_message = f'Congratulations, {user.username}!\n\nWe\'re glad you decided to join our community. We hope you have a great time using our service.'
    from_email = "info@cloudev-solutions.com"
    to_email = [user.email]
    # to_email = ["abdo.am169@gmail.com"]

    email = EmailMultiAlternatives(subject, text_message, from_email, to_email, )
    email.attach_alternative(html_message, 'text/html')
    email.send()


def send_verification_mail(user, verify_url, code):
    subject = 'Verify your email address'
    template_name = 'Email_verification.html'
    company_name = settings.DEFAULT_COMPANY_NAME
    support_mail = settings.DEFAULT_SUPPORT_EMAIL
    context = {'user': user, 'verify_url': verify_url, "code": code, "company_name": company_name,
               "support_mail": support_mail}
    html_message = render_to_string(template_name, context)
    text_message = ' '
    # from_email = 'testDevAcc20@outlook.com'
    from_email = settings.DEFAULT_FROM_EMAIL
    to_email = [user.email]
    email = EmailMultiAlternatives(subject, text_message, from_email, to_email, )
    email.attach_alternative(html_message, 'text/html', )
    email.send(fail_silently=False)


def send_passwordreset_verification_mail(user, reset_url, code):
    subject = 'reset password request'
    template_name = 'password_reset_verification.html'
    company_name = 'ClouDev-Solutions'
    support_mail = 'support@cloudev-solutions.com'
    context = {'user': user, 'reset_url': reset_url, "code": code, "company_name": company_name,
               "support_mail": support_mail}
    html_message = render_to_string(template_name, context)
    text_message = 'reset password request'
    from_email = 'testDevAcc20@outlook.com'
    to_email = [user.email]
    email = EmailMultiAlternatives(subject, text_message, from_email, to_email, )
    email.attach_alternative(html_message, 'text/html', )
    email.send(fail_silently=False)
