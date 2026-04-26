from django.urls import path
from . import views
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

urlpatterns = [
    # Auth endpoints
    path("register/", views.RegisterView.as_view(), name="register"),
    path("token/", TokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    
    # Project endpoints
    path("projects/", views.ProjectListCreateView.as_view(), name="projects"),
    path("projects/<int:pk>/", views.ProjectDetailView.as_view(), name="project_detail"),
    path("risk/", views.riskNoid.as_view(), name="Generated risks"),
    path("technology/", views.technologyNoid.as_view(), name="Get all technologies"),
    path("technology/<int:pk>/", views.technologyId.as_view(), name="Technology detail"),
    
    path("component/", views.componentNoid.as_view(), name="Get all components"),
    path("component/<int:pk>/", views.componentId.as_view(), name="Component detail"),
    path("damage_scenario/", views.damageScenarioNoid.as_view(), name="Get all damage scenarios"),
    path("damage_scenario/component/<int:pk>/", views.damageScenarioComponentId.as_view(), name="Damage scenario by component"),
    path("damage_scenario/<int:pk>/", views.damageScenarioId.as_view(), name="Damage scenario detail"),
    path("control_class/", views.ControlClassListView.as_view(), name="Control classes"),
    path("control/", views.controlNoid.as_view(), name="Get all controls"),
    path("control/component/<int:pk>/", views.controlComponentId.as_view(), name="Controls by component"),
    path("control/<int:pk>/", views.controlId.as_view(), name="Controls detail"),
    path("attack_step/", views.attackStepNoid.as_view(), name="Get all attack steps"),
    path("attack_step/component/<int:pk>/", views.attackStepComponentId.as_view(), name="Attack steps by component"),
    path("attack_step/<int:pk>/", views.attackStepId.as_view(), name="Attack step detail"),
    path("threat_scenario/", views.threatScenarioNoid.as_view(), name="Get all threat scenarios"),
    path("threat_scenario/component/<int:pk>/", views.threatScenarioComponentId.as_view(), name="Threat scenarios by component"),
    path("threat_scenario/<int:pk>/", views.threatScenarioId.as_view(), name="Threat scenario detail"),
    path("control_group/", views.controlGroupNoid.as_view(), name="Get all control groups"),
    path("control_group/<int:pk>/", views.controlGroupId.as_view(), name="Control group detail"),
    path("risk_treatment/", views.riskTreatmentView.as_view(), name="Risk treatment"),
    path("cybersecurity_goal/", views.cybersecurityGoalNoid.as_view(), name="Cybersecurity goals"),
    path("cybersecurity_goal/<int:pk>/", views.cybersecurityGoalId.as_view(), name="Cybersecurity goal detail"),
]
