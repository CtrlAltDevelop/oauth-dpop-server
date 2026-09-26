from django.urls import path

from authserver import views

app_name = "authserver"

urlpatterns = [
    path("authorize", views.authorize, name="authorize"),
    path("consent", views.consent, name="consent"),
    path("login", views.SignInView.as_view(), name="login"),
]
