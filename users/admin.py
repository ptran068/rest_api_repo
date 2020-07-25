from django.contrib import admin
from .models import CustomUser

# Register your models here.
class UserAmin(admin.ModelAdmin):
    # list_display = ['first_name', 'last_name', 'email', 'createdAt', 'updatedAt']
    # list_filter = ['createdAt', 'email']
    search_fields = ['email']

admin.site.register(CustomUser, UserAmin)
