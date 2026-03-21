from django.shortcuts import render
from rest_framework import generics, status
from rest_framework.response import Response
from .models import *
from .serializers import *
from rest_framework.views import APIView
from django.shortcuts import get_object_or_404

# GET/POST /nodes/
class getAllNodes(APIView):
    def get(self, request, format=None):
        nodes = Node.objects.all()
        serializer = NodeSerializer(nodes, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def post(self, request):
        json_body = request.data
        n = Node(title=json_body["title"], content=json_body["content"])
        n.save()
        return Response("you just posted", status=status.HTTP_200_OK)
    
# GET /nodes/<id>/
class getNodeDetail(APIView):
    def get(self, request, pk, format=None):
        nodes = Node.objects.filter(id=pk)
        serializer = NodeSerializer(nodes, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
class componentNoid(APIView):
    def get(self, request, format=None):
        components = Component.objects.all()
        serializer = ComponentSerializer(components, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        serializer = ComponentSerializer(data=request.data)
        if serializer.is_valid():
            component = serializer.save()
            # Handle many-to-many relationships
            if 'data_entities' in request.data:
                data_entities = DataEntity.objects.filter(id__in=request.data['data_entities'])
                component.data_entities.set(data_entities)
            if 'technologies' in request.data:
                technologies = Technology.objects.filter(id__in=request.data['technologies'])
                component.technology.set(technologies)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class componentId(APIView):
    def get(self, request, pk, format=None):
        component = get_object_or_404(Component, id=pk)
        serializer = ComponentDetailSerializer(component)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request, pk, format=None):
        component = get_object_or_404(Component, id=pk)
        serializer = ComponentSerializer(component, data=request.data, partial=True)
        if serializer.is_valid():
            component = serializer.save()
            # Handle many-to-many relationships
            if 'data_entity' in request.data:
                data_entities = []
                for de in request.data['data_entity']:
                    if isinstance(de, dict) and 'id' in de:
                        data_entity, created = DataEntity.objects.get_or_create(
                            id=de['id'],
                            defaults={'name': de.get('name', ''), 'description': de.get('description', '')}
                        )
                        data_entities.append(data_entity)
                    elif isinstance(de, int):
                        data_entities.append(DataEntity.objects.get(id=de))
                component.data_entities.set(data_entities)
            if 'technology' in request.data:
                technologies = []
                for tech in request.data['technology']:
                    if isinstance(tech, dict) and 'id' in tech:
                        technology, created = Technology.objects.get_or_create(
                            id=tech['id'],
                            defaults={'name': tech.get('name', ''), 'description': tech.get('description', '')}
                        )
                        technologies.append(technology)
                    elif isinstance(tech, int):
                        technologies.append(Technology.objects.get(id=tech))
                component.technology.set(technologies)
            if 'damage_scenario' in request.data:
                damage_scenarios = DamageScenario.objects.filter(id__in=request.data['damage_scenario'])
                component.damage_scenarios.set(damage_scenarios)
            if 'control' in request.data:
                controls = Control.objects.filter(id__in=request.data['control'])
                component.controls.set(controls)
            if 'threat_scenarios' in request.data:
                threat_scenarios = ThreatScenario.objects.filter(id__in=request.data['threat_scenarios'])
                component.threat_scenarios.set(threat_scenarios)
            if 'attack_steps' in request.data:
                attack_steps = AttackStep.objects.filter(id__in=request.data['attack_steps'])
                component.attack_steps.set(attack_steps)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class damageScenarioNoid(APIView):
    def get(self, request, format=None):
        damageScenarios = DamageScenario.objects.all()
        serializer = DamageScenarioSerializer(damageScenarios, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        serializer = DamageScenarioSerializer(data=request.data)
        if serializer.is_valid():
            damage_scenario = serializer.save()
            if 'threat_scenario_id' in request.data:
                threat_scenarios = ThreatScenario.objects.filter(id=request.data['threat_scenario_id'])
                damage_scenario.threat_scenarios.set(threat_scenarios)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class damageScenarioComponentId(APIView):
    def get(self, request, pk, format=None):
        damage_scenarios = DamageScenario.objects.filter(component_id=pk)
        serializer = DamageScenarioSerializer(damage_scenarios, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
class damageScenarioId(APIView):
    def get(self, request, pk, format=None):
        damage_scenario = get_object_or_404(DamageScenario, id=pk)
        serializer = DamageScenarioSerializer(damage_scenario)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request, pk, format=None):
        damage_scenario = get_object_or_404(DamageScenario, id=pk)
        serializer = DamageScenarioSerializer(damage_scenario, data=request.data, partial=True)
        if serializer.is_valid():
            damage_scenario = serializer.save()
            if 'threat_scenario_id' in request.data:
                threat_scenarios = ThreatScenario.objects.filter(id=request.data['threat_scenario_id'])
                damage_scenario.threat_scenarios.set(threat_scenarios)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class controlNoid(APIView):
    def get(self, request, format=None):
        controls = Control.objects.all()
        serializer = ControlSerializer(controls, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        serializer = ControlSerializer(data=request.data)
        if serializer.is_valid():
            control = serializer.save()
            if 'attack_steps' in request.data:
                attack_steps = AttackStep.objects.filter(id__in=request.data['attack_steps'])
                control.attack_steps.set(attack_steps)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class controlComponentId(APIView):
    def get(self, request, pk, format=None):
        controls = Control.objects.filter(component_id=pk)
        serializer = ControlSerializer(controls, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
class controlId(APIView):
    def get(self, request, pk, format=None):
        control = get_object_or_404(Control, id=pk)
        serializer = ControlDetailSerializer(control)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request, pk, format=None):
        control = get_object_or_404(Control, id=pk)
        serializer = ControlSerializer(control, data=request.data, partial=True)
        if serializer.is_valid():
            control = serializer.save()
            if 'attack_steps' in request.data:
                attack_steps = AttackStep.objects.filter(id__in=request.data['attack_steps'])
                control.attack_steps.set(attack_steps)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class attackStepNoid(APIView):
    def get(self, request, format=None):
        attack_steps = AttackStep.objects.all()
        serializer = AttackStepSerializer(attack_steps, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        serializer = AttackStepSerializer(data=request.data)
        if serializer.is_valid():
            attack_step = serializer.save()
            if 'prepared_by' in request.data:
                prepared_by = AttackStep.objects.filter(id__in=request.data['prepared_by'])
                attack_step.prepared_by.set(prepared_by)
            if 'threat_scenario' in request.data:
                threat_scenarios = ThreatScenario.objects.filter(id__in=request.data['threat_scenario'])
                attack_step.threat_scenarios.set(threat_scenarios)
            if 'controls' in request.data:
                controls = Control.objects.filter(id__in=request.data['controls'])
                attack_step.controls.set(controls)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class attackStepComponentId(APIView):
    def get(self, request, pk, format=None):
        attack_steps = AttackStep.objects.filter(component_id=pk)
        serializer = AttackStepSerializer(attack_steps, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
class attackStepId(APIView):
    def get(self, request, pk, format=None):
        attack_step = get_object_or_404(AttackStep, id=pk)
        serializer = AttackStepDetailSerializer(attack_step)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request, pk, format=None):
        attack_step = get_object_or_404(AttackStep, id=pk)
        serializer = AttackStepSerializer(attack_step, data=request.data, partial=True)
        if serializer.is_valid():
            attack_step = serializer.save()
            if 'prepared_by' in request.data:
                prepared_by = AttackStep.objects.filter(id__in=request.data['prepared_by'])
                attack_step.prepared_by.set(prepared_by)
            if 'threat_scenario' in request.data:
                threat_scenarios = ThreatScenario.objects.filter(id__in=request.data['threat_scenario'])
                attack_step.threat_scenarios.set(threat_scenarios)
            if 'controls' in request.data:
                controls = Control.objects.filter(id__in=request.data['controls'])
                attack_step.controls.set(controls)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class threatScenarioNoid(APIView):
    def get(self, request, format=None):
        threat_scenarios = ThreatScenario.objects.all()
        serializer = ThreatScenarioSerializer(threat_scenarios, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        serializer = ThreatScenarioSerializer(data=request.data)
        if serializer.is_valid():
            threat_scenario = serializer.save()
            if 'attack_step' in request.data:
                attack_steps = AttackStep.objects.filter(id__in=request.data['attack_step'])
                threat_scenario.attack_steps.set(attack_steps)
            if 'damage_scenario' in request.data:
                damage_scenarios = DamageScenario.objects.filter(id__in=request.data['damage_scenario'])
                threat_scenario.damage_scenarios.set(damage_scenarios)
            if 'compromises' in request.data:
                for comp in request.data['compromises']:
                    compromise, created = Comporomises.objects.get_or_create(
                        component_id=comp['component_id'],
                        compromised_CIA_part=comp['compromised_part_cia'],
                        threat_scenario=threat_scenario
                    )
                    threat_scenario.compromises.add(compromise)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class threatScenarioComponentId(APIView):
    def get(self, request, pk, format=None):
        # Filter threat scenarios by component through compromises
        threat_scenarios = ThreatScenario.objects.filter(compromises__component_id=pk).distinct()
        serializer = ThreatScenarioSerializer(threat_scenarios, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
class threatScenarioId(APIView):
    def get(self, request, pk, format=None):
        threat_scenario = get_object_or_404(ThreatScenario, id=pk)
        serializer = ThreatScenarioDetailSerializer(threat_scenario)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request, pk, format=None):
        threat_scenario = get_object_or_404(ThreatScenario, id=pk)
        serializer = ThreatScenarioSerializer(threat_scenario, data=request.data, partial=True)
        if serializer.is_valid():
            threat_scenario = serializer.save()
            if 'attack_step' in request.data:
                attack_steps = AttackStep.objects.filter(id__in=request.data['attack_step'])
                threat_scenario.attack_steps.set(attack_steps)
            if 'damage_scenario' in request.data:
                damage_scenarios = DamageScenario.objects.filter(id__in=request.data['damage_scenario'])
                threat_scenario.damage_scenarios.set(damage_scenarios)
            if 'compromises' in request.data:
                # Clear existing compromises and add new ones
                threat_scenario.compromises_relation.all().delete()
                for comp in request.data['compromises']:
                    compromise = Comporomises.objects.create(
                        component_id=comp['component_id'],
                        compromised_CIA_part=comp['compromised_part_cia'],
                        threat_scenario=threat_scenario
                    )
                    threat_scenario.compromises.add(compromise)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)