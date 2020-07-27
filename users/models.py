from django.db import models
from django.contrib.auth.models import AbstractUser
from .managers import CustomUserManager
import uuid

class CustomUser(AbstractUser):
    username = None
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    email = models.EmailField(('email address'), unique=True)
    image = models.ImageField(blank=True, null=True, default='cover3.jpeg', upload_to='profile_pics')
    cover_photos = models.ImageField(blank=True, null=True,default='cover3.jpeg',upload_to='cover_pics')
    follower = models.IntegerField(blank=True, null=True,default=0)
    following = models.IntegerField(blank=True, null=True,default=0)
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = CustomUserManager()

    def __str__(self):
        return self.email
        