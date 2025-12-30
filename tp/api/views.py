from django.shortcuts import render
from rest_framework import generics, status
from rest_framework.response import Response
from .models import Node
from .serializers import NodeSerializer
from rest_framework.views import APIView

# Create your views here.
class getAllNodes(APIView):
    def get(self, request, format=None):
        nodes = Node.objects.all()
        serializer = NodeSerializer(nodes, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def post(self, request):
        # todo: get data from request
        n = Node(title="mynewnode", content="contentt")
        n.save()
        return Response("you just posted", status=status.HTTP_200_OK)