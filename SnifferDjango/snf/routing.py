from django.urls import path
from .consumers import SniffConsumer

ws_urlpatterns = [
    path("ws/sniff/<str:interface>", SniffConsumer.as_asgi())
]