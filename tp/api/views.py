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

# GET/POST /nodes/
class getAllNodes(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, format=None):
        project_id = request.query_params.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)
        
        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)
        
        nodes = Node.objects.all()
        serializer = NodeSerializer(nodes, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def post(self, request):
        project_id = request.data.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)
        
        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)
        
        json_body = request.data
        n = Node(title=json_body["title"], content=json_body["content"])
        n.save()
        return Response("you just posted", status=status.HTTP_200_OK)
    
# GET /nodes/<id>/
class getNodeDetail(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, pk, format=None):
        project_id = request.query_params.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)
        
        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)
        
        nodes = Node.objects.filter(id=pk)
        serializer = NodeSerializer(nodes, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
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
    
    def delete(self, request, pk):
        project = get_object_or_404(Project, id=pk, owner=request.user)
        project.delete()
        return Response({'message': 'Project deleted'}, status=status.HTTP_204_NO_CONTENT)
    
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

    def post(self, request, pk, format=None):
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
                data_entities = []
                for de in request.data['data_entities']:
                    if isinstance(de, dict) and 'id' in de:
                        data_entity, created = DataEntity.objects.get_or_create(
                            id=de['id'],
                            defaults={'name': de.get('name', ''), 'description': de.get('description', ''), 'project': project}
                        )
                        data_entities.append(data_entity)
                    elif isinstance(de, int):
                        data_entities.append(DataEntity.objects.get(id=de, project=project))
                component.data_entities.set(data_entities)
            if 'technologies' in request.data:
                technologies = []
                for tech in request.data['technologies']:
                    if isinstance(tech, dict) and 'id' in tech:
                        technology, created = Technology.objects.get_or_create(
                            id=tech['id'],
                            defaults={'name': tech.get('name', ''), 'description': tech.get('description', ''), 'project': project}
                        )
                        technologies.append(technology)
                    elif isinstance(tech, int):
                        technologies.append(Technology.objects.get(id=tech, project=project))
                component.technology.set(technologies)
            if 'damage_scenarios' in request.data:
                damage_scenarios = DamageScenario.objects.filter(id__in=request.data['damage_scenarios'], project=project)
                component.damage_scenarios.set(damage_scenarios)
            if 'controls' in request.data:
                controls = Control.objects.filter(id__in=request.data['controls'], project=project)
                component.controls.set(controls)
            if 'threat_scenarios' in request.data:
                threat_scenarios = ThreatScenario.objects.filter(id__in=request.data['threat_scenarios'], project=project)
                component.threat_scenarios.set(threat_scenarios)
            if 'attack_steps' in request.data:
                attack_steps = AttackStep.objects.filter(id__in=request.data['attack_steps'], project=project)
                component.attack_steps.set(attack_steps)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
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
        
        serializer = DamageScenarioSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(project=project)
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
        serializer = DamageScenarioSerializer(damage_scenario)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request, pk, format=None):
        project_id = request.data.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)
        
        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)
        
        damage_scenario = get_object_or_404(DamageScenario, id=pk, project=project)
        serializer = DamageScenarioSerializer(damage_scenario, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
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

    def post(self, request, pk, format=None):
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
        
        serializer = AttackStepSerializer(data=request.data)
        if serializer.is_valid():
            attack_step = serializer.save(project=project)
            if 'prepared_by' in request.data:
                prepared_by = AttackStep.objects.filter(id__in=request.data['prepared_by'], project=project)
                attack_step.prepared_by.set(prepared_by)
            if 'threat_scenarios' in request.data:
                threat_scenarios = ThreatScenario.objects.filter(id__in=request.data['threat_scenarios'], project=project)
                attack_step.threat_scenarios.set(threat_scenarios)
            if 'controls' in request.data:
                controls = Control.objects.filter(id__in=request.data['controls'], project=project)
                attack_step.controls.set(controls)
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

    def post(self, request, pk, format=None):
        project_id = request.data.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)
        
        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)
        
        attack_step = get_object_or_404(AttackStep, id=pk, project=project)
        serializer = AttackStepSerializer(attack_step, data=request.data, partial=True)
        if serializer.is_valid():
            attack_step = serializer.save()
            if 'prepared_by' in request.data:
                prepared_by = AttackStep.objects.filter(id__in=request.data['prepared_by'], project=project)
                attack_step.prepared_by.set(prepared_by)
            if 'threat_scenarios' in request.data:
                threat_scenarios = ThreatScenario.objects.filter(id__in=request.data['threat_scenarios'], project=project)
                attack_step.threat_scenarios.set(threat_scenarios)
            if 'controls' in request.data:
                controls = Control.objects.filter(id__in=request.data['controls'], project=project)
                attack_step.controls.set(controls)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
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
        
        serializer = ThreatScenarioSerializer(data=request.data)
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
                        compromised_CIA_part=comp['compromised_part_cia'],
                        threat_scenario=threat_scenario,
                        project=project
                    )
                    threat_scenario.compromises.add(compromise)
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
        
        threat_scenarios = ThreatScenario.objects.filter(compromises__component_id=pk, project=project).distinct()
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

    def post(self, request, pk, format=None):
        project_id = request.data.get('project_id')
        if not project_id:
            return Response({'error': 'project_id required'}, status=status.HTTP_400_BAD_REQUEST)
        
        project = check_project_access(request.user, project_id)
        if not project:
            return Response({'error': 'Project not found or access denied'}, status=status.HTTP_403_FORBIDDEN)
        
        threat_scenario = get_object_or_404(ThreatScenario, id=pk, project=project)
        serializer = ThreatScenarioSerializer(threat_scenario, data=request.data, partial=True)
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
                        compromised_CIA_part=comp['compromised_part_cia'],
                        threat_scenario=threat_scenario,
                        project=project
                    )
                    threat_scenario.compromises.add(compromise)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)