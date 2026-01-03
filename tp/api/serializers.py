from rest_framework import serializers
from .models import *

class NodeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Node
        fields = ["id", "title", "content"]

class TechnologySerializer(serializers.ModelSerializer):
    class Meta:
        model = Technology
        fields = ["id", "name", "description"]
        extra_kwargs = {
            'name': {'max_length': 100},
            'description': {'max_length': 500}
        }

class ComponentSerializer(serializers.ModelSerializer):
    communicates_with = serializers.PrimaryKeyRelatedField(
        many=True, 
        queryset=Component.objects.all(), 
        required=False
    )
    technology = serializers.PrimaryKeyRelatedField(
        many=True, 
        queryset=Technology.objects.all(), 
        required=False
    )
    
    class Meta:
        model = Component
        fields = ["id", "name", "description", "communicates_with", "technology"]
        extra_kwargs = {
            'name': {'max_length': 100},
            'description': {'max_length': 500}
        }

class DataEntitySerializer(serializers.ModelSerializer):
    technology = serializers.PrimaryKeyRelatedField(
        many=True, 
        queryset=Technology.objects.all()
    )
    
    class Meta:
        model = DataEntity
        fields = ["id", "name", "description", "component", "technology"]
        extra_kwargs = {
            'name': {'max_length': 100},
            'description': {'max_length': 500}
        }

class ControlSerializer(serializers.ModelSerializer):
    class Meta:
        model = Control
        fields = ["id", "name", "fr_et", "fr_se", "fr_koC", "fr_WoO", "fr_eq", "component"]
        extra_kwargs = {
            'name': {'max_length': 100},
            'fr_et': {'max_length': 100},
            'fr_se': {'max_length': 100},
            'fr_koC': {'max_length': 100},
            'fr_WoO': {'max_length': 100},
            'fr_eq': {'max_length': 100}
        }

class ThreatClassSerializer(serializers.ModelSerializer):
    class Meta:
        model = ThreatClass
        fields = ["id", "name", "description"]
        extra_kwargs = {
            'name': {'max_length': 100},
            'description': {'max_length': 500}
        }

class AttackStepSerializer(serializers.ModelSerializer):
    control = serializers.PrimaryKeyRelatedField(
        many=True, 
        queryset=Control.objects.all(),
        required=False
    )
    prepared_by = serializers.PrimaryKeyRelatedField(
        many=True, 
        queryset=AttackStep.objects.all(), 
        required=False
    )
    
    class Meta:
        model = AttackStep
        fields = [
            "id", "name", "fr_et", "fr_se", "fr_koC", "fr_WoO", "fr_eq", 
            "component", "control", "prepared_by", "threat_class"
        ]
        extra_kwargs = {
            'name': {'max_length': 100},
            'fr_et': {'max_length': 100},
            'fr_se': {'max_length': 100},
            'fr_koC': {'max_length': 100},
            'fr_WoO': {'max_length': 100},
            'fr_eq': {'max_length': 100}
        }

class ThreatScenarioSerializer(serializers.ModelSerializer):
    class Meta:
        model = ThreatScenario
        fields = ["id", "name", "attackStep", "threat_class"]
        extra_kwargs = {
            'name': {'max_length': 100}
        }

class DamageScenarioSerializer(serializers.ModelSerializer):
    class Meta:
        model = DamageScenario
        fields = [
            "id", "name", "affected_CIA_parts", "impact_scale", 
            "safety_impact", "finantial_impact", "operational_impact", 
            "privacy_impact", "component", "threat_scenario"
        ]
        extra_kwargs = {
            'name': {'max_length': 100},
            'impact_scale': {'max_length': 50},
            'safety_impact': {'max_length': 100},
            'finantial_impact': {'max_length': 100},
            'operational_impact': {'max_length': 100},
            'privacy_impact': {'max_length': 100}
        }

class ComporomisesSerializer(serializers.ModelSerializer):
    class Meta:
        model = Comporomises
        fields = ["id", "compromised_CIA_part", "threat_scenario", "component"]
        extra_kwargs = {
            'compromised_CIA_part': {'max_length': 100}
        }