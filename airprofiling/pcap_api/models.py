from django.db import models
from django.conf import settings
from django.db.models.signals import post_save
from django.dispatch import receiver
from rest_framework.authtoken.models import Token

UPLOADS_DIR = getattr(settings, "UPLOADS_DIR", "uploads")

@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_auth_token(sender, instance=None, created=False, **kwargs):
    """
    Crea un token de autenticación al crear un usuario
    """
    if created:
        Token.objects.create(user=instance)


class PcapFile(models.Model):
    """
    Modelo del archivo pcap a guardar
    """
    class Meta:
        app_label = 'pcap_api' # <-- this label was wrong before.

    FILE_STATUS = (
        (0, 'New'),
        (1, 'Parsed'),
        (2, 'Analyzed'),
        (-1, 'Error')
    )
    
    # Datos del archivo
    file = models.FileField(upload_to=UPLOADS_DIR, default='', blank=True, null=True)
    name = models.CharField(max_length=100)
    description = models.CharField(max_length=500, default='')
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    owner = models.ForeignKey('auth.User', related_name="pcap_file_owner", default=None)
    #modifier = models.ForeignKey('auth.User', related_name="pcap_file_modifier", default=None)
    size = models.IntegerField(default=0)
    status = models.IntegerField(choices=FILE_STATUS, default=0)

    # Datos del procesado del pcap
    parsed_date = models.DateTimeField(auto_now_add=False, null=True, blank=True)
    parsed_json = models.CharField(max_length=10000000, default='')

    # Datos del análisis del pcap
    analyzed_date = models.DateTimeField(auto_now_add=False, null=True, blank=True)
    analyzed_json = models.CharField(max_length=10000000, default='')

    class Meta:
        ordering = ('created',)
