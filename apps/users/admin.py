from django.contrib import admin

from apps.users.models import User


@admin.register(User)
class User(admin.ModelAdmin):
    pass