# posts/models.py
from django.db import models
from django.utils import timezone
from django.urls import reverse
from django.utils.timezone import now
from PIL import Image
from django.conf import settings
import uuid

class Image(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    name = models.TextField(max_length = 500, null = True, blank = True)
    link  = models.TextField(max_length=500, null = True, blank = True)
    timestamp = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return self.caption

    def get_absolute_url(self):
        return reverse('index')

