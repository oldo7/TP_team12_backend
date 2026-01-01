from django.shortcuts import render
from rest_framework import generics, status
from rest_framework.response import Response
from .models import Node
from .serializers import NodeSerializer
from rest_framework.views import APIView
import json

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