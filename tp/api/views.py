from django.db import transaction
from django.db.models import Q
from django.shortcuts import render
from rest_framework import generics, status
from rest_framework.response import Response
from .models import *
from .serializers import *
from .calculations import (
    best_attack_feasibility_for_threat_scenario,
    calculate_impact_level,
    calculate_risk_level,
    impact_level_label,
)
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
        component = getattr(instance, 'component', None)
        if component is not None and hasattr(instance, 'threat_scenarios'):
            for threat_scenario in instance.threat_scenarios.filter(project=project):
                threat_scenario.components.add(component)
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
    component = getattr(instance, 'component', None)
    if component is not None:
        for threat_scenario in threat_scenarios:
            threat_scenario.components.add(component)


def sync_threat_scenario_components(threat_scenario, project, payload):
    if 'components' in payload:
        component_ids = payload.get('components', [])
        if not isinstance(component_ids, (list, tuple)):
            component_ids = [component_ids]
        components = list(Component.objects.filter(id__in=component_ids, project=project))
        threat_scenario.components.set(components)

    attack_step_components = Component.objects.filter(
        attack_steps__threat_scenarios=threat_scenario,
        project=project,
    ).distinct()
    threat_scenario.components.add(*attack_step_components)

    compromise_components = Component.objects.filter(
        compromises__threat_scenario=threat_scenario,
        project=project,
    ).distinct()
    threat_scenario.components.add(*compromise_components)


def allowed_damage_concern_components(damage_scenario, project):
    return Component.objects.filter(
        threat_scenarios__damage_scenarios=damage_scenario,
        project=project,
    ).distinct()


def sync_damage_scenario_cia_summary(damage_scenario, force=False):
    concerns = list(damage_scenario.concerns.all())
    if not concerns and not force:
        return

    cia_summary = CIABitmask.NONE
    for concern in concerns:
        cia_summary |= concern.affected_CIA_parts

    if damage_scenario.affected_CIA_parts != cia_summary:
        damage_scenario.affected_CIA_parts = cia_summary
        damage_scenario.save(update_fields=['affected_CIA_parts'])


def prune_invalid_damage_scenario_concerns(damage_scenario, project):
    had_concerns = damage_scenario.concerns.exists()
    allowed_component_ids = set(
        allowed_damage_concern_components(damage_scenario, project)
        .values_list('id', flat=True)
    )
    damage_scenario.concerns.exclude(component_id__in=allowed_component_ids).delete()
    sync_damage_scenario_cia_summary(damage_scenario, force=had_concerns)


def prune_damage_scenario_concerns_for_threat_scenario(threat_scenario, project):
    for damage_scenario in threat_scenario.damage_scenarios.filter(project=project):
        prune_invalid_damage_scenario_concerns(damage_scenario, project)


def sync_damage_scenario_concerns(damage_scenario, project, payload):
    if 'concerns' not in payload:
        prune_invalid_damage_scenario_concerns(damage_scenario, project)
        return

    concerns_payload = payload.get('concerns') or []
    allowed_component_ids = set(
        allowed_damage_concern_components(damage_scenario, project)
        .values_list('id', flat=True)
    )

    next_component_ids = set()
    for concern_payload in concerns_payload:
        component_id = concern_payload.get('component')
        if component_id is None:
            raise ValueError('Each concern must include a component.')
        component_id = int(component_id)
        if component_id not in allowed_component_ids:
            raise ValueError(
                'Damage scenario concerns can only reference components from linked threat scenarios.'
            )

        affected_cia_parts = parse_cia_bitmask(concern_payload.get('affected_CIA_parts'))
        if affected_cia_parts == CIABitmask.NONE:
            continue

        component = get_object_or_404(Component, id=component_id, project=project)
        DamageScenarioConcern.objects.update_or_create(
            damage_scenario=damage_scenario,
            component=component,
            defaults={'affected_CIA_parts': affected_cia_parts},
        )
        next_component_ids.add(component_id)

    damage_scenario.concerns.exclude(component_id__in=next_component_ids).delete()
    sync_damage_scenario_cia_summary(damage_scenario, force=True)


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
        if attack_step.component is not None:
            threat_scenario.components.add(attack_step.component)
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
        project=project,
    )

    for threat_scenario in threat_scenarios:
        threat_scenario.attack_steps.add(attack_step)
        if attack_step.component is not None:
            threat_scenario.components.add(attack_step.component)
        threat_scenario.damage_scenarios.add(damage_scenario)

    return damage_scenario

class ControlClassListView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        classes = ControlClass.objects.all()
        serializer = ControlClassSerializer(classes, many=True)
        return Response(serializer.data)


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


class riskNoid(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        project_id = request.query_params.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)

        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)

        treatments = {
            (t.threat_scenario_id, t.damage_scenario_id): t
            for t in RiskTreatment.objects.filter(project=project)
        }

        rows = []
        threat_scenarios = (
            ThreatScenario.objects
            .filter(project=project)
            .prefetch_related(
                'attack_steps',
                'attack_steps__previous_steps',
                'damage_scenarios',
                'damage_scenarios__concerns',
                'damage_scenarios__concerns__component',
            )
        )

        for threat_scenario in threat_scenarios:
            attack_feasibility = best_attack_feasibility_for_threat_scenario(threat_scenario)
            for damage_scenario in threat_scenario.damage_scenarios.all():
                impact_level = calculate_impact_level(damage_scenario)
                risk_level = calculate_risk_level(
                    impact_level,
                    attack_feasibility['afl_value'],
                )
                concerns = list(damage_scenario.concerns.all())

                sfop = {
                    'safety_impact': damage_scenario.safety_impact,
                    'finantial_impact': damage_scenario.finantial_impact,
                    'operational_impact': damage_scenario.operational_impact,
                    'privacy_impact': damage_scenario.privacy_impact,
                }

                treatment = treatments.get((threat_scenario.id, damage_scenario.id))
                treatment_data = {
                    'treatment_decision': treatment.decision if treatment else None,
                    'treatment_rationale': treatment.rationale if treatment else '',
                }

                if not concerns and damage_scenario.affected_CIA_parts:
                    rows.append({
                        'id': f'ts-{threat_scenario.id}-ds-{damage_scenario.id}-legacy',
                        'title': f'{threat_scenario.name} / {damage_scenario.name}',
                        'threat_scenario': threat_scenario.id,
                        'threat_scenario_name': threat_scenario.name,
                        'damage_scenario': damage_scenario.id,
                        'damage_scenario_name': damage_scenario.name,
                        'concern': None,
                        'component': None,
                        'component_name': None,
                        'affected_CIA_parts': damage_scenario.affected_CIA_parts,
                        'il': impact_level,
                        'il_label': impact_level_label(impact_level),
                        'rl': risk_level,
                        **sfop,
                        **treatment_data,
                        **attack_feasibility,
                    })
                    continue

                for concern in concerns:
                    rows.append({
                        'id': f'ts-{threat_scenario.id}-ds-{damage_scenario.id}-concern-{concern.id}',
                        'title': f'{threat_scenario.name} / {damage_scenario.name} / {concern.component.name}',
                        'threat_scenario': threat_scenario.id,
                        'threat_scenario_name': threat_scenario.name,
                        'damage_scenario': damage_scenario.id,
                        'damage_scenario_name': damage_scenario.name,
                        'concern': concern.id,
                        'component': concern.component_id,
                        'component_name': concern.component.name,
                        'affected_CIA_parts': concern.affected_CIA_parts,
                        'il': impact_level,
                        'il_label': impact_level_label(impact_level),
                        'rl': risk_level,
                        **sfop,
                        **treatment_data,
                        **attack_feasibility,
                    })

        return Response(rows, status=status.HTTP_200_OK)

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
            try:
                with transaction.atomic():
                    damage_scenario = serializer.save(project=project)
                    sync_threat_scenarios(damage_scenario, project, request.data)
                    sync_damage_scenario_concerns(damage_scenario, project, request.data)
            except ValueError as error:
                return Response({'concerns': [str(error)]}, status=status.HTTP_400_BAD_REQUEST)
            return Response(DamageScenarioSerializer(damage_scenario).data, status=status.HTTP_201_CREATED)
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
        
        damage_scenarios = DamageScenario.objects.filter(
            threat_scenarios__components__id=pk,
            project=project,
        ).distinct()
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
            try:
                with transaction.atomic():
                    damage_scenario = serializer.save()
                    sync_threat_scenarios(damage_scenario, project, request.data)
                    sync_damage_scenario_concerns(damage_scenario, project, request.data)
            except ValueError as error:
                return Response({'concerns': [str(error)]}, status=status.HTTP_400_BAD_REQUEST)
            return Response(DamageScenarioSerializer(damage_scenario).data, status=status.HTTP_200_OK)
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
            try:
                with transaction.atomic():
                    damage_scenario = serializer.save()
                    sync_threat_scenarios(damage_scenario, project, request.data)
                    sync_damage_scenario_concerns(damage_scenario, project, request.data)
            except ValueError as error:
                return Response({'concerns': [str(error)]}, status=status.HTTP_400_BAD_REQUEST)
            return Response(DamageScenarioSerializer(damage_scenario).data, status=status.HTTP_200_OK)
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
        
        controls = Control.objects.filter(
            Q(component_id=pk) | Q(attack_steps__component_id=pk),
            project=project,
        ).distinct()
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
            sync_threat_scenario_components(threat_scenario, project, request.data)
            prune_damage_scenario_concerns_for_threat_scenario(threat_scenario, project)
            if 'compromises' in request.data:
                for comp in request.data['compromises']:
                    compromise, created = Comporomises.objects.get_or_create(
                        component_id=comp['component_id'],
                        compromised_CIA_part=parse_cia_bitmask(comp['compromised_part_cia']),
                        threat_scenario=threat_scenario,
                        project=project
                    )
                sync_threat_scenario_components(threat_scenario, project, request.data)
                prune_damage_scenario_concerns_for_threat_scenario(threat_scenario, project)
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
        
        threat_scenarios = ThreatScenario.objects.filter(components__id=pk, project=project).distinct()
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
            sync_threat_scenario_components(threat_scenario, project, request.data)
            prune_damage_scenario_concerns_for_threat_scenario(threat_scenario, project)
            if 'compromises' in request.data:
                threat_scenario.compromise_items.all().delete()
                for comp in request.data['compromises']:
                    compromise = Comporomises.objects.create(
                        component_id=comp['component_id'],
                        compromised_CIA_part=parse_cia_bitmask(comp['compromised_part_cia']),
                        threat_scenario=threat_scenario,
                        project=project
                    )
                sync_threat_scenario_components(threat_scenario, project, request.data)
                prune_damage_scenario_concerns_for_threat_scenario(threat_scenario, project)
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
            sync_threat_scenario_components(threat_scenario, project, request.data)
            prune_damage_scenario_concerns_for_threat_scenario(threat_scenario, project)
            if 'compromises' in request.data:
                threat_scenario.compromise_items.all().delete()
                for comp in request.data['compromises']:
                    compromise = Comporomises.objects.create(
                        component_id=comp['component_id'],
                        compromised_CIA_part=parse_cia_bitmask(comp['compromised_part_cia']),
                        threat_scenario=threat_scenario,
                        project=project
                    )
                sync_threat_scenario_components(threat_scenario, project, request.data)
                prune_damage_scenario_concerns_for_threat_scenario(threat_scenario, project)
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


# CONTROL GROUP ENDPOINTS
class controlGroupNoid(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        project_id = request.query_params.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)

        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)

        groups = ControlGroup.objects.filter(project=project).prefetch_related('controls')
        serializer = ControlGroupDetailSerializer(groups, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        project_id = request.data.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)

        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)

        serializer = ControlGroupSerializer(data=request.data)
        if serializer.is_valid():
            group = serializer.save(project=project)
            if 'controls' in request.data:
                controls = Control.objects.filter(id__in=request.data['controls'], project=project)
                group.controls.set(controls)
            return Response(ControlGroupDetailSerializer(group).data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class controlGroupId(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, pk, format=None):
        project_id = request.query_params.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)

        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)

        group = get_object_or_404(ControlGroup, id=pk, project=project)
        serializer = ControlGroupDetailSerializer(group)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, pk, format=None):
        project_id = request.data.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)

        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)

        group = get_object_or_404(ControlGroup, id=pk, project=project)
        serializer = ControlGroupSerializer(group, data=request.data)
        if serializer.is_valid():
            group = serializer.save()
            controls = Control.objects.filter(id__in=request.data.get('controls', []), project=project)
            group.controls.set(controls)
            return Response(ControlGroupDetailSerializer(group).data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, pk, format=None):
        project_id = request.data.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)

        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)

        group = get_object_or_404(ControlGroup, id=pk, project=project)
        serializer = ControlGroupSerializer(group, data=request.data, partial=True)
        if serializer.is_valid():
            group = serializer.save()
            if 'controls' in request.data:
                controls = Control.objects.filter(id__in=request.data['controls'], project=project)
                group.controls.set(controls)
            return Response(ControlGroupDetailSerializer(group).data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk, format=None):
        project_id = request.data.get('project_id') or request.query_params.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)

        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)

        group = get_object_or_404(ControlGroup, id=pk, project=project)
        group.delete()
        return Response({'message': 'Control group deleted successfully'}, status=status.HTTP_204_NO_CONTENT)


class reportView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from django.http import HttpResponse
        from .report import generate_report_pdf

        project_id = request.query_params.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)

        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)

        pdf_bytes = generate_report_pdf(project)
        response  = HttpResponse(pdf_bytes, content_type='application/pdf')
        safe_name = project.name.replace(' ', '_')
        response['Content-Disposition'] = f'attachment; filename="tara-{safe_name}.pdf"'
        return response


class cybersecurityGoalNoid(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        project_id = request.query_params.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)
        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)
        goals = CybersecurityGoal.objects.filter(project=project).prefetch_related('damage_scenarios', 'controls')
        return Response(CybersecurityGoalDetailSerializer(goals, many=True).data)

    def post(self, request, format=None):
        project_id = request.data.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)
        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)
        serializer = CybersecurityGoalSerializer(data=request.data)
        if serializer.is_valid():
            goal = serializer.save()
            return Response(CybersecurityGoalDetailSerializer(goal).data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class cybersecurityGoalId(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, pk, format=None):
        project_id = request.query_params.get('project_id')
        project = check_project_access(request.user, project_id) if project_id else None
        goal = get_object_or_404(CybersecurityGoal, id=pk)
        if project and goal.project != project:
            return Response({'error': 'Access denied'}, status=status.HTTP_403_FORBIDDEN)
        return Response(CybersecurityGoalDetailSerializer(goal).data)

    def put(self, request, pk, format=None):
        project_id = request.data.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)
        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)
        goal = get_object_or_404(CybersecurityGoal, id=pk, project=project)
        serializer = CybersecurityGoalSerializer(goal, data=request.data)
        if serializer.is_valid():
            goal = serializer.save()
            if 'damage_scenarios' in request.data:
                goal.damage_scenarios.set(
                    DamageScenario.objects.filter(id__in=request.data['damage_scenarios'], project=project))
            if 'controls' in request.data:
                goal.controls.set(
                    Control.objects.filter(id__in=request.data['controls'], project=project))
            return Response(CybersecurityGoalDetailSerializer(goal).data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, pk, format=None):
        project_id = request.data.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)
        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)
        goal = get_object_or_404(CybersecurityGoal, id=pk, project=project)
        serializer = CybersecurityGoalSerializer(goal, data=request.data, partial=True)
        if serializer.is_valid():
            goal = serializer.save()
            if 'damage_scenarios' in request.data:
                goal.damage_scenarios.set(
                    DamageScenario.objects.filter(id__in=request.data['damage_scenarios'], project=project))
            if 'controls' in request.data:
                goal.controls.set(
                    Control.objects.filter(id__in=request.data['controls'], project=project))
            return Response(CybersecurityGoalDetailSerializer(goal).data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk, format=None):
        project_id = request.data.get('project_id') or request.query_params.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)
        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)
        goal = get_object_or_404(CybersecurityGoal, id=pk, project=project)
        goal.delete()
        return Response({'message': 'Cybersecurity goal deleted'}, status=status.HTTP_204_NO_CONTENT)


class riskTreatmentView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def put(self, request, format=None):
        project_id = request.data.get('project_id') or request.query_params.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)

        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)

        ts_id = request.data.get('threat_scenario')
        ds_id = request.data.get('damage_scenario')
        decision = request.data.get('decision') or ''
        rationale = request.data.get('rationale', '')

        if not ts_id or not ds_id:
            return Response(
                {'error': 'threat_scenario and damage_scenario are required'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            ts = ThreatScenario.objects.get(id=ts_id, project=project)
            ds = DamageScenario.objects.get(id=ds_id, project=project)
        except (ThreatScenario.DoesNotExist, DamageScenario.DoesNotExist):
            return Response(
                {'error': 'Invalid threat_scenario or damage_scenario'},
                status=status.HTTP_404_NOT_FOUND,
            )

        if not decision:
            RiskTreatment.objects.filter(threat_scenario=ts, damage_scenario=ds).delete()
            return Response({'message': 'Treatment cleared'}, status=status.HTTP_200_OK)

        if decision not in RiskTreatmentDecision.values:
            return Response(
                {'error': f'Invalid decision. Must be one of: {list(RiskTreatmentDecision.values)}'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        treatment, _ = RiskTreatment.objects.update_or_create(
            threat_scenario=ts,
            damage_scenario=ds,
            defaults={'decision': decision, 'rationale': rationale, 'project': project},
        )
        return Response(RiskTreatmentSerializer(treatment).data, status=status.HTTP_200_OK)
