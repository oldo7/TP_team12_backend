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
    
    # example JSON: {"title": "mytitle", "content": "contesttest"}
    def post(self, request):
        json_body = request.data
        n = Node(title=json_body["title"], content=json_body["content"])
        n.save()
        return Response("you just posted", status=status.HTTP_200_OK)
    
# GET /nodes/<id>/
class getNodeDetail(APIView):
    def get(self, request, pk, format=None):
        nodes = Node.objects.filter(id=pk)
        print("nodes: ", nodes)
        serializer = NodeSerializer(nodes, many = True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
class componentNoid(APIView):
    def get(self, request, format=None):
        components = Component.objects.all()
        serializer = ComponentSerializer(components, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        json_body = request.data
        n = Component(name=json_body["name"], description=json_body["description"])
        n.save()
        return Response("you just posted", status=status.HTTP_200_OK)
    
class componentId(APIView):
    def get(self, request, pk, format=None):
        components = Component.objects.filter(id=pk)
        serializer = ComponentSerializer(components, many = True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request, pk, format=None):
        component = get_object_or_404(Component, id=pk)
        serializer = ComponentSerializer(component, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response("component NOT updated", status=status.HTTP_200_OK)
    
class damageScenarioNoid(APIView):
    def get(self, request, format=None):
        damageScenarios = DamageScenario.objects.all()
        serializer = DamageScenarioSerializer(damageScenarios, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        json_body = request.data
        n = DamageScenario(name=json_body["name"], affected_CIA_parts=json_body["affected_CIA_parts"],               
                      impact_scale=json_body["impact_scale"],
                      safety_impact=json_body["safety_impact"],
                      finantial_impact=json_body["finantial_impact"],
                      operational_impact=json_body["operational_impact"],
                      privacy_impact=json_body["privacy_impact"],
                      )
        n.save()
        return Response("you just posted", status=status.HTTP_200_OK)
    
class damageScenarioComponentId(APIView):
    def get(self, request, pk, format=None):

        return Response(f"get damage scenarios with component id {pk}", status=status.HTTP_200_OK)
    
class damageScenarioId(APIView):
    def get(self, request, pk, format=None):

        return Response(f"get damage scenario with id {pk}", status=status.HTTP_200_OK)

    def post(self, request):
        json_body = request.data
        return Response("ds NOT updated", status=status.HTTP_200_OK)
    
class controlNoid(APIView):
    def get(self, request, format=None):

        return Response(f"get all controls", status=status.HTTP_200_OK)

    def post(self, request):
        json_body = request.data
        return Response("control NOT created", status=status.HTTP_200_OK)

class controlComponentId(APIView):
    def get(self, request, pk, format=None):

        return Response(f"get controls with component id {pk}", status=status.HTTP_200_OK)
    
class controlId(APIView):
    def get(self, request, pk, format=None):

        return Response(f"get control with id {pk}", status=status.HTTP_200_OK)

    def post(self, request):
        json_body = request.data
        return Response("control NOT updated", status=status.HTTP_200_OK)
    
class attackStepNoid(APIView):
    def get(self, request, format=None):

        return Response(f"get all attack steps", status=status.HTTP_200_OK)

    def post(self, request):
        json_body = request.data
        return Response("attack step not created", status=status.HTTP_200_OK)
    
class attackStepComponentId(APIView):
    def get(self, request, pk, format=None):

        return Response(f"get attack steps with component id {pk}", status=status.HTTP_200_OK)
    
class attackStepId(APIView):
    def get(self, request, pk, format=None):

        return Response(f"get attack step with id {pk}", status=status.HTTP_200_OK)

    def post(self, request):
        json_body = request.data
        return Response("attack steps NOT updated", status=status.HTTP_200_OK)
    
class threatScenarioNoid(APIView):
    def get(self, request, format=None):

        return Response(f"get all threatScenarios", status=status.HTTP_200_OK)

    def post(self, request):
        json_body = request.data
        return Response("threat scenario not created", status=status.HTTP_200_OK)
    
class threatScenarioComponentId(APIView):
    def get(self, request, pk, format=None):

        return Response(f"get threat scenarios with component id {pk}", status=status.HTTP_200_OK)
    
class threatScenarioId(APIView):
    def get(self, request, pk, format=None):

        return Response(f"get threat scenario with id {pk}", status=status.HTTP_200_OK)

    def post(self, request):
        json_body = request.data
        return Response("threat scenario NOT updated", status=status.HTTP_200_OK)