from django import forms
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import authenticate
from django.contrib import messages
from django.conf import settings

class AdvancedLoginForm(AuthenticationForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Customize authentication_form field labels
        self.fields['username'].label = 'Username or Email'
        self.fields['password'].label = 'Password'

        self.fields['username'].widget.attrs.update(
            {'class': 'authentication_form-control', 'placeholder': 'Username or Email', 'required': 'required'})
        self.fields['password'].widget.attrs.update(
            {'class': 'authentication_form-control', 'placeholder': 'Password', 'required': 'required'})


    def clean(self):
        cleaned_data = super().clean()
        username = cleaned_data.get('username')
        password = cleaned_data.get('password')

        if username and password:
            # Authenticate user with both username and email
            user = authenticate(username=username, password=password)

            if user is None:
                # Raise a validation error for invalid credentials
                raise forms.ValidationError('Invalid username/email or password.')

        return cleaned_data
