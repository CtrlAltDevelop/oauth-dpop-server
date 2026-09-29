from django.contrib import admin
from django.urls import include, path

from authserver.api import api as oauth_api
from demo_api.api import api as demo_api

urlpatterns = [
    path("admin/", admin.site.urls),
    path("oauth/", include("authserver.urls")),
    path("api/", demo_api.urls),
    path("", oauth_api.urls),
]
