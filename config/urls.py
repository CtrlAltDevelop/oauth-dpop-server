from django.contrib import admin
from django.urls import path

from authserver.api import api as oauth_api

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", oauth_api.urls),
]
