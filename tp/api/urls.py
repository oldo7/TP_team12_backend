from django.urls import path
from . import views

urlpatterns = [
    path("nodes/", views.getAllNodes.as_view(), name="Get all views"),
]
