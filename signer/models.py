import secrets
from django.db import models

class ApiUser(models.Model):
    email = models.EmailField(unique=True)
    name = models.CharField(max_length=150)
    password_hash = models.CharField(max_length=128)
    cert_file = models.FileField(upload_to='certificates/')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.email


class ApiClient(models.Model):
    name = models.CharField(max_length=100)
    api_key = models.CharField(max_length=40, unique=True, editable=False)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if not self.api_key:
            self.api_key = secrets.token_hex(20)  # 40 karakter hex
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.name} ({'aktif' if self.is_active else 'nonaktif'})"
    
class PdfSignLog(models.Model):
    email = models.EmailField()
    ip_address = models.GenericIPAddressField()
    status = models.CharField(max_length=100)
    message = models.TextField()
    filename = models.CharField(max_length=1024, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
