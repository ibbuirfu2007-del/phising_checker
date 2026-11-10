from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User


class CustomUserCreationForm(UserCreationForm):

    username = forms.CharField(
        max_length=150,
        label="Name",
        help_text=""
    )

    class Meta:
        model = User
        fields = ["username", "password1", "password2"]