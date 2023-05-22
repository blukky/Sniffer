from django.urls import path
from .views import *


urlpatterns = [
    path("", main, name="main"),
    path("journal", journal, name="journal"),
    path("anomal", anomal, name="anomal"),
    path("stat", stat, name="stat"),
    path("create_portrait", create_portrait, name="create_portrait"),
    path("show_portrait", show_portrait, name="show_portrait"),
]