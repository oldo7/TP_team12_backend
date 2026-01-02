from django.urls import path
from . import views

urlpatterns = [
    path("nodes/", views.getAllNodes.as_view(), name="Get all nodes"),
    path("nodes/<int:pk>/", views.getNodeDetail.as_view(), name="Node detail"),
    path("component/", views.componentNoid.as_view(), name="Get all components"),
    path("component/<int:pk>/", views.componentId.as_view(), name="Component detail"),
    path("damage_scenario/", views.damageScenarioNoid.as_view(), name="Get all damage scenarios"),
    path("damage_scenario/component/<int:pk>/", views.damageScenarioComponentId.as_view(), name="Damage scenario by component"),
    path("damage_scenario/<int:pk>/", views.damageScenarioId.as_view(), name="Damage scenario detail"),
    path("control/", views.controlNoid.as_view(), name="Get all controls"),
    path("control/component/<int:pk>/", views.controlComponentId.as_view(), name="Controls by component"),
    path("control/<int:pk>/", views.controlId.as_view(), name="Controls detail"),
    path("attack_step/", views.attackStepNoid.as_view(), name="Get all attack steps"),
    path("attack_step/component/<int:pk>/", views.attackStepComponentId.as_view(), name="Attack steps by component"),
    path("attack_step/<int:pk>/", views.attackStepId.as_view(), name="Attack step detail"),
    path("threat_scenario/", views.threatScenarioNoid.as_view(), name="Get all threat scenarios"),
    path("threat_scenario/component/<int:pk>/", views.threatScenarioComponentId.as_view(), name="Threat scenarios by component"),
    path("threat_scenario/<int:pk>/", views.threatScenarioId.as_view(), name="Threat scenario detail"),
]
