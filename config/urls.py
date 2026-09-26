from django.contrib import admin
from django.urls import include, path

from authserver.api import api as oauth_api

urlpatterns = [
    path("admin/", admin.site.urls),
    path("oauth/", include("authserver.urls")),
    path("", oauth_api.urls),
]
