from django.db import transaction
from django.shortcuts import render
from rest_framework import generics, status
from rest_framework.response import Response
from .models import *
from .serializers import *
from rest_framework.views import APIView
from django.shortcuts import get_object_or_404
from django.contrib.auth.models import User
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication

# Helper function to check project access
def check_project_access(user, project_id):
    try:
        project = Project.objects.get(id=project_id, owner=user)
        return project
    except Project.DoesNotExist:
        return None


def build_serializer_payload(request, remove_fields=None):
    payload = request.data.copy()
    fields_to_remove = {'threat_scenario_name'}
    if remove_fields:
        fields_to_remove.update(remove_fields)
    for field_name in fields_to_remove:
        payload.pop(field_name, None)
    return payload


def parse_cia_bitmask(value):
    if value is None:
        return CIABitmask.NONE

    normalized = str(value).strip().lower().replace(',', '').replace(' ', '')
    aliases = {
        '': CIABitmask.NONE,
        '0': CIABitmask.NONE,
        '000': CIABitmask.NONE,
        'none': CIABitmask.NONE,
        'availability': CIABitmask.AVAILABILITY,
        'a': CIABitmask.AVAILABILITY,
        '1': CIABitmask.AVAILABILITY,
        '001': CIABitmask.AVAILABILITY,
        'integrity': CIABitmask.INTEGRITY,
        'i': CIABitmask.INTEGRITY,
        '2': CIABitmask.INTEGRITY,
        '010': CIABitmask.INTEGRITY,
        'confidentiality': CIABitmask.CONFIDENTIALITY,
        'c': CIABitmask.CONFIDENTIALITY,
        '4': CIABitmask.CONFIDENTIALITY,
        '100': CIABitmask.CONFIDENTIALITY,
        'ia': CIABitmask.INTEGRITY | CIABitmask.AVAILABILITY,
        '011': CIABitmask.INTEGRITY | CIABitmask.AVAILABILITY,
        'ca': CIABitmask.CONFIDENTIALITY | CIABitmask.AVAILABILITY,
        '101': CIABitmask.CONFIDENTIALITY | CIABitmask.AVAILABILITY,
        'ci': CIABitmask.CONFIDENTIALITY | CIABitmask.INTEGRITY,
        '110': CIABitmask.CONFIDENTIALITY | CIABitmask.INTEGRITY,
        'cia': CIABitmask.CONFIDENTIALITY | CIABitmask.INTEGRITY | CIABitmask.AVAILABILITY,
        'all': CIABitmask.CONFIDENTIALITY | CIABitmask.INTEGRITY | CIABitmask.AVAILABILITY,
        '111': CIABitmask.CONFIDENTIALITY | CIABitmask.INTEGRITY | CIABitmask.AVAILABILITY,
    }
    if normalized in aliases:
        return aliases[normalized]
    raise ValueError(f'Unsupported CIA bitmask value: {value!r}')


def sync_threat_scenarios(instance, project, payload):
    if 'threat_scenarios' not in payload and 'threat_scenario_name' not in payload:
        return

    if hasattr(payload, 'getlist'):
        threat_scenario_ids = payload.getlist('threat_scenarios')
    else:
        threat_scenario_ids = payload.get('threat_scenarios', [])

    if 'threat_scenarios' in payload:
        if not isinstance(threat_scenario_ids, (list, tuple)):
            threat_scenario_ids = [threat_scenario_ids]
        threat_scenarios = list(
            ThreatScenario.objects.filter(id__in=threat_scenario_ids, project=project)
        )
    else:
        threat_scenarios = list(instance.threat_scenarios.all())

    threat_scenario_name = payload.get('threat_scenario_name')
    if isinstance(threat_scenario_name, list):
        threat_scenario_name = threat_scenario_name[0] if threat_scenario_name else ''

    if threat_scenario_name:
        defaults = {}
        threat_class = getattr(instance, 'threat_class', None)
        if threat_class is not None:
            defaults['threat_class'] = threat_class

        threat_scenario, _ = ThreatScenario.objects.get_or_create(
            name=threat_scenario_name,
            project=project,
            defaults=defaults,
        )
        if all(existing.id != threat_scenario.id for existing in threat_scenarios):
            threat_scenarios.append(threat_scenario)

    instance.threat_scenarios.set(threat_scenarios)


def truncate_model_name(model_class, value):
    max_length = model_class._meta.get_field('name').max_length
    return value[:max_length]


def create_damage_scenario_for_attack_step(attack_step, project):
    threat_scenarios = list(attack_step.threat_scenarios.filter(project=project))

    if not threat_scenarios:
        threat_scenario = ThreatScenario.objects.create(
            name=truncate_model_name(
                ThreatScenario,
                f'Threat scenario for {attack_step.name}',
            ),
            description=attack_step.description,
            threat_class=attack_step.threat_class,
            project=project,
        )
        threat_scenario.attack_steps.add(attack_step)
        threat_scenarios = [threat_scenario]

    damage_scenario = DamageScenario.objects.create(
        name=truncate_model_name(
            DamageScenario,
            f'Damage scenario for {attack_step.name}',
        ),
        description=attack_step.description,
        affected_CIA_parts=CIABitmask.NONE,
        impact_scale=ImpactRating.NEGLIGIBLE,
        safety_impact=ImpactRating.NEGLIGIBLE,
        finantial_impact=ImpactRating.NEGLIGIBLE,
        operational_impact=ImpactRating.NEGLIGIBLE,
        privacy_impact=ImpactRating.NEGLIGIBLE,
        component=attack_step.component,
        project=project,
    )

    for threat_scenario in threat_scenarios:
        threat_scenario.attack_steps.add(attack_step)
        threat_scenario.damage_scenarios.add(damage_scenario)

    return damage_scenario

class RegisterView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        email = request.data.get('email', '')
        
        if User.objects.filter(username=username).exists():
            return Response({'error': 'Username already exists'}, status=status.HTTP_400_BAD_REQUEST)
        
        user = User.objects.create_user(username=username, password=password, email=email)
        return Response({'message': 'User created successfully'}, status=status.HTTP_201_CREATED)

class ProjectListCreateView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        projects = request.user.projects.all()
        serializer = ProjectSerializer(projects, many=True)
        return Response(serializer.data)
    
    def post(self, request):
        serializer = ProjectSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(owner=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ProjectDetailView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, pk):
        project = get_object_or_404(Project, id=pk, owner=request.user)
        serializer = ProjectSerializer(project)
        return Response(serializer.data)
    
    def put(self, request, pk):
        project = get_object_or_404(Project, id=pk, owner=request.user)
        serializer = ProjectSerializer(project, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def patch(self, request, pk):
        project = get_object_or_404(Project, id=pk, owner=request.user)
        serializer = ProjectSerializer(project, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, pk):
        project = get_object_or_404(Project, id=pk, owner=request.user)
        project.delete()
        return Response({'message': 'Project deleted'}, status=status.HTTP_204_NO_CONTENT)

# TECHNOLOGY ENDPOINTS
class technologyNoid(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, format=None):
        project_id = request.query_params.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)
        
        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)
        
        technologies = Technology.objects.filter(project=project)
        serializer = TechnologySerializer(technologies, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        project_id = request.data.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)
        
        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)
        
        serializer = TechnologySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(project=project)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class technologyId(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, pk, format=None):
        project_id = request.query_params.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)
        
        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)
        
        technology = get_object_or_404(Technology, id=pk, project=project)
        serializer = TechnologySerializer(technology)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, pk, format=None):
        project_id = request.data.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)
        
        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)
        
        technology = get_object_or_404(Technology, id=pk, project=project)
        serializer = TechnologySerializer(technology, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, pk, format=None):
        project_id = request.data.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)
        
        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)
        
        technology = get_object_or_404(Technology, id=pk, project=project)
        serializer = TechnologySerializer(technology, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk, format=None):
        project_id = request.data.get('project_id') or request.query_params.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)
        
        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)
        
        technology = get_object_or_404(Technology, id=pk, project=project)
        technology.delete()
        return Response({'message': 'Technology deleted successfully'}, status=status.HTTP_204_NO_CONTENT)

# COMPONENT ENDPOINTS
class componentNoid(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, format=None):
        project_id = request.query_params.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)
        
        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)
        
        components = Component.objects.filter(project=project)
        serializer = ComponentSerializer(components, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        project_id = request.data.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)
        
        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)
        
        serializer = ComponentSerializer(data=request.data)
        if serializer.is_valid():
            component = serializer.save(project=project)
            if 'data_entities' in request.data:
                data_entities = DataEntity.objects.filter(id__in=request.data['data_entities'], project=project)
                component.data_entities.set(data_entities)
            if 'technologies' in request.data:
                technologies = Technology.objects.filter(id__in=request.data['technologies'], project=project)
                component.technology.set(technologies)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class componentId(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, pk, format=None):
        project_id = request.query_params.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)
        
        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)
        
        component = get_object_or_404(Component, id=pk, project=project)
        serializer = ComponentDetailSerializer(component)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, pk, format=None):
        project_id = request.data.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)
        
        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)
        
        component = get_object_or_404(Component, id=pk, project=project)
        serializer = ComponentSerializer(component, data=request.data)
        if serializer.is_valid():
            component = serializer.save()
            if 'data_entities' in request.data:
                data_entities = DataEntity.objects.filter(id__in=request.data['data_entities'], project=project)
                component.data_entities.set(data_entities)
            if 'technologies' in request.data:
                technologies = Technology.objects.filter(id__in=request.data['technologies'], project=project)
                component.technology.set(technologies)
            if 'damage_scenarios' in request.data:
                damage_scenarios = DamageScenario.objects.filter(id__in=request.data['damage_scenarios'], project=project)
                component.damage_scenarios.set(damage_scenarios)
            if 'controls' in request.data:
                controls = Control.objects.filter(id__in=request.data['controls'], project=project)
                component.controls.set(controls)
            if 'attack_steps' in request.data:
                attack_steps = AttackStep.objects.filter(id__in=request.data['attack_steps'], project=project)
                component.attack_steps.set(attack_steps)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, pk, format=None):
        project_id = request.data.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)
        
        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)
        
        component = get_object_or_404(Component, id=pk, project=project)
        serializer = ComponentSerializer(component, data=request.data, partial=True)
        if serializer.is_valid():
            component = serializer.save()
            if 'data_entities' in request.data:
                data_entities = DataEntity.objects.filter(id__in=request.data['data_entities'], project=project)
                component.data_entities.set(data_entities)
            if 'technologies' in request.data:
                technologies = Technology.objects.filter(id__in=request.data['technologies'], project=project)
                component.technology.set(technologies)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk, format=None):
        project_id = request.data.get('project_id') or request.query_params.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)
        
        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)
        
        component = get_object_or_404(Component, id=pk, project=project)
        component.delete()
        return Response({'message': 'Component deleted successfully'}, status=status.HTTP_204_NO_CONTENT)

# DAMAGE SCENARIO ENDPOINTS
class damageScenarioNoid(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, format=None):
        project_id = request.query_params.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)
        
        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)
        
        damageScenarios = DamageScenario.objects.filter(project=project)
        serializer = DamageScenarioSerializer(damageScenarios, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        project_id = request.data.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)
        
        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)
        
        serializer = DamageScenarioSerializer(data=build_serializer_payload(request))
        if serializer.is_valid():
            damage_scenario = serializer.save(project=project)
            sync_threat_scenarios(damage_scenario, project, request.data)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class damageScenarioComponentId(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, pk, format=None):
        project_id = request.query_params.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)
        
        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)
        
        damage_scenarios = DamageScenario.objects.filter(component_id=pk, project=project)
        serializer = DamageScenarioSerializer(damage_scenarios, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
class damageScenarioId(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, pk, format=None):
        project_id = request.query_params.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)
        
        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)
        
        damage_scenario = get_object_or_404(DamageScenario, id=pk, project=project)
        serializer = DamageScenarioDetailSerializer(damage_scenario)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, pk, format=None):
        project_id = request.data.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)
        
        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)
        
        damage_scenario = get_object_or_404(DamageScenario, id=pk, project=project)
        serializer = DamageScenarioSerializer(damage_scenario, data=build_serializer_payload(request))
        if serializer.is_valid():
            damage_scenario = serializer.save()
            sync_threat_scenarios(damage_scenario, project, request.data)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, pk, format=None):
        project_id = request.data.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)
        
        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)
        
        damage_scenario = get_object_or_404(DamageScenario, id=pk, project=project)
        serializer = DamageScenarioSerializer(damage_scenario, data=build_serializer_payload(request), partial=True)
        if serializer.is_valid():
            damage_scenario = serializer.save()
            sync_threat_scenarios(damage_scenario, project, request.data)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk, format=None):
        project_id = request.data.get('project_id') or request.query_params.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)
        
        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)
        
        damage_scenario = get_object_or_404(DamageScenario, id=pk, project=project)
        damage_scenario.delete()
        return Response({'message': 'Damage scenario deleted successfully'}, status=status.HTTP_204_NO_CONTENT)

# CONTROL ENDPOINTS
class controlNoid(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, format=None):
        project_id = request.query_params.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)
        
        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)
        
        controls = Control.objects.filter(project=project)
        serializer = ControlSerializer(controls, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        project_id = request.data.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)
        
        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)
        
        serializer = ControlSerializer(data=request.data)
        if serializer.is_valid():
            control = serializer.save(project=project)
            if 'attack_steps' in request.data:
                attack_steps = AttackStep.objects.filter(id__in=request.data['attack_steps'], project=project)
                control.attack_steps.set(attack_steps)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class controlComponentId(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, pk, format=None):
        project_id = request.query_params.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)
        
        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)
        
        controls = Control.objects.filter(component_id=pk, project=project)
        serializer = ControlSerializer(controls, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
class controlId(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, pk, format=None):
        project_id = request.query_params.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)
        
        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)
        
        control = get_object_or_404(Control, id=pk, project=project)
        serializer = ControlDetailSerializer(control)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, pk, format=None):
        project_id = request.data.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)
        
        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)
        
        control = get_object_or_404(Control, id=pk, project=project)
        serializer = ControlSerializer(control, data=request.data)
        if serializer.is_valid():
            control = serializer.save()
            if 'attack_steps' in request.data:
                attack_steps = AttackStep.objects.filter(id__in=request.data['attack_steps'], project=project)
                control.attack_steps.set(attack_steps)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, pk, format=None):
        project_id = request.data.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)
        
        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)
        
        control = get_object_or_404(Control, id=pk, project=project)
        serializer = ControlSerializer(control, data=request.data, partial=True)
        if serializer.is_valid():
            control = serializer.save()
            if 'attack_steps' in request.data:
                attack_steps = AttackStep.objects.filter(id__in=request.data['attack_steps'], project=project)
                control.attack_steps.set(attack_steps)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk, format=None):
        project_id = request.data.get('project_id') or request.query_params.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)
        
        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)
        
        control = get_object_or_404(Control, id=pk, project=project)
        control.delete()
        return Response({'message': 'Control deleted successfully'}, status=status.HTTP_204_NO_CONTENT)

# ATTACK STEP ENDPOINTS
class attackStepNoid(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, format=None):
        project_id = request.query_params.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)
        
        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)
        
        attack_steps = AttackStep.objects.filter(project=project)
        serializer = AttackStepSerializer(attack_steps, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        project_id = request.data.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)
        
        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)
        
        serializer = AttackStepSerializer(data=build_serializer_payload(request))
        if serializer.is_valid():
            with transaction.atomic():
                attack_step = serializer.save(project=project)
                if 'previous_steps' in request.data:
                    previous_steps = AttackStep.objects.filter(id__in=request.data['previous_steps'], project=project)
                    attack_step.previous_steps.set(previous_steps)
                sync_threat_scenarios(attack_step, project, request.data)
                if 'controls' in request.data:
                    controls = Control.objects.filter(id__in=request.data['controls'], project=project)
                    attack_step.controls.set(controls)
                create_damage_scenario_for_attack_step(attack_step, project)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class attackStepComponentId(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, pk, format=None):
        project_id = request.query_params.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)
        
        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)
        
        attack_steps = AttackStep.objects.filter(component_id=pk, project=project)
        serializer = AttackStepSerializer(attack_steps, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
class attackStepId(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, pk, format=None):
        project_id = request.query_params.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)
        
        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)
        
        attack_step = get_object_or_404(AttackStep, id=pk, project=project)
        serializer = AttackStepDetailSerializer(attack_step)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, pk, format=None):
        project_id = request.data.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)
        
        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)
        
        attack_step = get_object_or_404(AttackStep, id=pk, project=project)
        serializer = AttackStepSerializer(attack_step, data=build_serializer_payload(request))
        if serializer.is_valid():
            attack_step = serializer.save()
            if 'previous_steps' in request.data:
                previous_steps = AttackStep.objects.filter(id__in=request.data['previous_steps'], project=project)
                attack_step.previous_steps.set(previous_steps)
            sync_threat_scenarios(attack_step, project, request.data)
            if 'controls' in request.data:
                controls = Control.objects.filter(id__in=request.data['controls'], project=project)
                attack_step.controls.set(controls)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, pk, format=None):
        project_id = request.data.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)
        
        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)
        
        attack_step = get_object_or_404(AttackStep, id=pk, project=project)
        serializer = AttackStepSerializer(attack_step, data=build_serializer_payload(request), partial=True)
        if serializer.is_valid():
            attack_step = serializer.save()
            if 'previous_steps' in request.data:
                previous_steps = AttackStep.objects.filter(id__in=request.data['previous_steps'], project=project)
                attack_step.previous_steps.set(previous_steps)
            sync_threat_scenarios(attack_step, project, request.data)
            if 'controls' in request.data:
                controls = Control.objects.filter(id__in=request.data['controls'], project=project)
                attack_step.controls.set(controls)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk, format=None):
        project_id = request.data.get('project_id') or request.query_params.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)
        
        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)
        
        attack_step = get_object_or_404(AttackStep, id=pk, project=project)
        attack_step.delete()
        return Response({'message': 'Attack step deleted successfully'}, status=status.HTTP_204_NO_CONTENT)

# THREAT SCENARIO ENDPOINTS
class threatScenarioNoid(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, format=None):
        project_id = request.query_params.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)
        
        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)
        
        threat_scenarios = ThreatScenario.objects.filter(project=project)
        serializer = ThreatScenarioSerializer(threat_scenarios, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        project_id = request.data.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)
        
        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)
        
        serializer = ThreatScenarioSerializer(
            data=build_serializer_payload(request, remove_fields={'compromises'})
        )
        if serializer.is_valid():
            threat_scenario = serializer.save(project=project)
            if 'attack_steps' in request.data:
                attack_steps = AttackStep.objects.filter(id__in=request.data['attack_steps'], project=project)
                threat_scenario.attack_steps.set(attack_steps)
            if 'damage_scenarios' in request.data:
                damage_scenarios = DamageScenario.objects.filter(id__in=request.data['damage_scenarios'], project=project)
                threat_scenario.damage_scenarios.set(damage_scenarios)
            if 'compromises' in request.data:
                for comp in request.data['compromises']:
                    compromise, created = Comporomises.objects.get_or_create(
                        component_id=comp['component_id'],
                        compromised_CIA_part=parse_cia_bitmask(comp['compromised_part_cia']),
                        threat_scenario=threat_scenario,
                        project=project
                    )
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class threatScenarioComponentId(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, pk, format=None):
        project_id = request.query_params.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)
        
        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)
        
        threat_scenarios = ThreatScenario.objects.filter(
            compromise_items__component_id=pk,
            project=project,
        ).distinct()
        serializer = ThreatScenarioSerializer(threat_scenarios, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
class threatScenarioId(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, pk, format=None):
        project_id = request.query_params.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)
        
        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)
        
        threat_scenario = get_object_or_404(ThreatScenario, id=pk, project=project)
        serializer = ThreatScenarioDetailSerializer(threat_scenario)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, pk, format=None):
        project_id = request.data.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)
        
        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)
        
        threat_scenario = get_object_or_404(ThreatScenario, id=pk, project=project)
        serializer = ThreatScenarioSerializer(
            threat_scenario,
            data=build_serializer_payload(request, remove_fields={'compromises'})
        )
        if serializer.is_valid():
            threat_scenario = serializer.save()
            if 'attack_steps' in request.data:
                attack_steps = AttackStep.objects.filter(id__in=request.data['attack_steps'], project=project)
                threat_scenario.attack_steps.set(attack_steps)
            if 'damage_scenarios' in request.data:
                damage_scenarios = DamageScenario.objects.filter(id__in=request.data['damage_scenarios'], project=project)
                threat_scenario.damage_scenarios.set(damage_scenarios)
            if 'compromises' in request.data:
                threat_scenario.compromise_items.all().delete()
                for comp in request.data['compromises']:
                    compromise = Comporomises.objects.create(
                        component_id=comp['component_id'],
                        compromised_CIA_part=parse_cia_bitmask(comp['compromised_part_cia']),
                        threat_scenario=threat_scenario,
                        project=project
                    )
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, pk, format=None):
        project_id = request.data.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)
        
        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)
        
        threat_scenario = get_object_or_404(ThreatScenario, id=pk, project=project)
        serializer = ThreatScenarioSerializer(
            threat_scenario,
            data=build_serializer_payload(request, remove_fields={'compromises'}),
            partial=True
        )
        if serializer.is_valid():
            threat_scenario = serializer.save()
            if 'attack_steps' in request.data:
                attack_steps = AttackStep.objects.filter(id__in=request.data['attack_steps'], project=project)
                threat_scenario.attack_steps.set(attack_steps)
            if 'damage_scenarios' in request.data:
                damage_scenarios = DamageScenario.objects.filter(id__in=request.data['damage_scenarios'], project=project)
                threat_scenario.damage_scenarios.set(damage_scenarios)
            if 'compromises' in request.data:
                threat_scenario.compromise_items.all().delete()
                for comp in request.data['compromises']:
                    compromise = Comporomises.objects.create(
                        component_id=comp['component_id'],
                        compromised_CIA_part=parse_cia_bitmask(comp['compromised_part_cia']),
                        threat_scenario=threat_scenario,
                        project=project
                    )
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk, format=None):
        project_id = request.data.get('project_id') or request.query_params.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)
        
        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)
        
        threat_scenario = get_object_or_404(ThreatScenario, id=pk, project=project)
        threat_scenario.delete()
        return Response({'message': 'Threat scenario deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
