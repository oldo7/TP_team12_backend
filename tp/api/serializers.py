from rest_framework import serializers
from .models import *
from django.contrib.auth.models import User

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email']

class ProjectSerializer(serializers.ModelSerializer):
    owner = UserSerializer(read_only=True)
    
    class Meta:
        model = Project
        fields = ['id', 'name', 'description', 'owner', 'created_at']

class NodeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Node
        fields = ["id", "title", "content"]

class TechnologySerializer(serializers.ModelSerializer):
    project_id = serializers.PrimaryKeyRelatedField(
        source='project',
        queryset=Project.objects.all(),
        required=True,
        write_only=True
    )
    
    class Meta:
        model = Technology
        fields = ["id", "name", "description", "project", "project_id"]
        extra_kwargs = {
            'name': {'max_length': 100},
            'description': {'max_length': 500},
            'project': {'read_only': True}
        }

class DataEntitySerializer(serializers.ModelSerializer):
    project_id = serializers.PrimaryKeyRelatedField(
        source='project',
        queryset=Project.objects.all(),
        required=True,
        write_only=True
    )
    
    class Meta:
        model = DataEntity
        fields = ["id", "name", "description", "project", "project_id"]
        extra_kwargs = {
            'name': {'max_length': 100},
            'description': {'max_length': 500},
            'project': {'read_only': True}
        }

class ControlSimpleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Control
        fields = ["id", "name"]

class AttackStepSimpleSerializer(serializers.ModelSerializer):
    class Meta:
        model = AttackStep
        fields = ["id", "name"]

class DamageScenarioSimpleSerializer(serializers.ModelSerializer):
    class Meta:
        model = DamageScenario
        fields = ["id", "name", "affected_CIA_parts", "impact_scale", "safety_impact", 
                  "finantial_impact", "operational_impact", "privacy_impact"]

class ThreatScenarioSimpleSerializer(serializers.ModelSerializer):
    class Meta:
        model = ThreatScenario
        fields = ["id", "name"]

class DamageScenarioSerializer(serializers.ModelSerializer):
    threat_scenario_id = serializers.PrimaryKeyRelatedField(
        source='threat_scenario',
        queryset=ThreatScenario.objects.all(),
        required=False,
        allow_null=True
    )
    component_id = serializers.PrimaryKeyRelatedField(
        source='component',
        queryset=Component.objects.all(),
        required=False,
        allow_null=True
    )
    project_id = serializers.PrimaryKeyRelatedField(
        source='project',
        queryset=Project.objects.all(),
        required=True,
        write_only=True
    )
    
    class Meta:
        model = DamageScenario
        fields = [
            "id", "name", "affected_CIA_parts", "impact_scale", 
            "safety_impact", "finantial_impact", "operational_impact", 
            "privacy_impact", "component_id", "threat_scenario_id", "project", "project_id"
        ]
        extra_kwargs = {
            'name': {'max_length': 100},
            'impact_scale': {'max_length': 50},
            'safety_impact': {'max_length': 100},
            'finantial_impact': {'max_length': 100},
            'operational_impact': {'max_length': 100},
            'privacy_impact': {'max_length': 100},
            'project': {'read_only': True}
        }

class ControlSerializer(serializers.ModelSerializer):
    attack_steps = serializers.PrimaryKeyRelatedField(
        many=True, 
        queryset=AttackStep.objects.all(), 
        required=False
    )
    project_id = serializers.PrimaryKeyRelatedField(
        source='project',
        queryset=Project.objects.all(),
        required=True,
        write_only=True
    )
    
    class Meta:
        model = Control
        fields = ["id", "name", "fr_et", "fr_se", "fr_koC", "fr_WoO", "fr_eq", "component", "attack_steps", "project", "project_id"]
        extra_kwargs = {
            'name': {'max_length': 100},
            'fr_et': {'max_length': 100},
            'fr_se': {'max_length': 100},
            'fr_koC': {'max_length': 100},
            'fr_WoO': {'max_length': 100},
            'fr_eq': {'max_length': 100},
            'project': {'read_only': True}
        }

class ControlDetailSerializer(serializers.ModelSerializer):
    attack_steps = AttackStepSimpleSerializer(many=True, read_only=True)
    
    class Meta:
        model = Control
        fields = ["id", "name", "fr_et", "fr_se", "fr_koC", "fr_WoO", "fr_eq", "component", "attack_steps", "project"]

class ThreatClassSerializer(serializers.ModelSerializer):
    project_id = serializers.PrimaryKeyRelatedField(
        source='project',
        queryset=Project.objects.all(),
        required=True,
        write_only=True
    )
    
    class Meta:
        model = ThreatClass
        fields = ["id", "name", "description", "project", "project_id"]
        extra_kwargs = {
            'name': {'max_length': 100},
            'description': {'max_length': 500},
            'project': {'read_only': True}
        }

class AttackStepSerializer(serializers.ModelSerializer):
    prepared_by = serializers.PrimaryKeyRelatedField(
        many=True, 
        queryset=AttackStep.objects.all(), 
        required=False
    )
    threat_scenario = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=ThreatScenario.objects.all(),
        required=False
    )
    controls = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=Control.objects.all(),
        required=False
    )
    project_id = serializers.PrimaryKeyRelatedField(
        source='project',
        queryset=Project.objects.all(),
        required=True,
        write_only=True
    )
    
    class Meta:
        model = AttackStep
        fields = [
            "id", "name", "fr_et", "fr_se", "fr_koC", "fr_WoO", "fr_eq", 
            "component", "prepared_by", "threat_class", "threat_scenario", "controls", "project", "project_id"
        ]
        extra_kwargs = {
            'name': {'max_length': 100},
            'fr_et': {'max_length': 100},
            'fr_se': {'max_length': 100},
            'fr_koC': {'max_length': 100},
            'fr_WoO': {'max_length': 100},
            'fr_eq': {'max_length': 100},
            'project': {'read_only': True}
        }

class AttackStepDetailSerializer(serializers.ModelSerializer):
    prepared_by = AttackStepSimpleSerializer(many=True, read_only=True)
    threat_scenario = ThreatScenarioSimpleSerializer(many=True, read_only=True)
    controls = ControlSimpleSerializer(many=True, read_only=True)
    threat_class = ThreatClassSerializer(read_only=True)
    
    class Meta:
        model = AttackStep
        fields = [
            "id", "name", "fr_et", "fr_se", "fr_koC", "fr_WoO", "fr_eq", 
            "component", "prepared_by", "threat_class", "threat_scenario", "controls", "project"
        ]

class ThreatScenarioSerializer(serializers.ModelSerializer):
    attack_step = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=AttackStep.objects.all(),
        required=False
    )
    damage_scenario = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=DamageScenario.objects.all(),
        required=False
    )
    compromises = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=Comporomises.objects.all(),
        required=False
    )
    project_id = serializers.PrimaryKeyRelatedField(
        source='project',
        queryset=Project.objects.all(),
        required=True,
        write_only=True
    )
    
    class Meta:
        model = ThreatScenario
        fields = ["id", "name", "attack_step", "damage_scenario", "threat_class", "compromises", "project", "project_id"]
        extra_kwargs = {
            'name': {'max_length': 100},
            'project': {'read_only': True}
        }

class ThreatScenarioDetailSerializer(serializers.ModelSerializer):
    attack_step = AttackStepSimpleSerializer(many=True, read_only=True)
    damage_scenario = DamageScenarioSimpleSerializer(many=True, read_only=True)
    threat_class = ThreatClassSerializer(read_only=True)
    compromises = serializers.SerializerMethodField()
    
    class Meta:
        model = ThreatScenario
        fields = ["id", "name", "attack_step", "damage_scenario", "threat_class", "compromises", "project"]
    
    def get_compromises(self, obj):
        return [{"component_id": c.component_id, "compromised_part_cia": c.compromised_CIA_part} 
                for c in obj.compromise_items.all()]

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
    data_entity = DataEntitySerializer(many=True, read_only=True)
    project_id = serializers.PrimaryKeyRelatedField(
        source='project',
        queryset=Project.objects.all(),
        required=True,
        write_only=True
    )
    
    class Meta:
        model = Component
        fields = ["id", "name", "description", "communicates_with", "technology", "data_entity", "project", "project_id"]
        extra_kwargs = {
            'name': {'max_length': 100},
            'description': {'max_length': 500},
            'project': {'read_only': True}
        }

class ComponentDetailSerializer(serializers.ModelSerializer):
    data_entity = DataEntitySerializer(many=True, read_only=True)
    technology = TechnologySerializer(many=True, read_only=True)
    damage_scenario = DamageScenarioSerializer(many=True, read_only=True, source='damage_scenarios')
    control = ControlDetailSerializer(many=True, read_only=True, source='controls')
    threat_scenarios = ThreatScenarioSimpleSerializer(many=True, read_only=True)
    attack_steps = AttackStepSimpleSerializer(many=True, read_only=True)
    
    class Meta:
        model = Component
        fields = ["id", "name", "description", "data_entity", "technology", "damage_scenario", 
                  "control", "threat_scenarios", "attack_steps", "project"]

class ComporomisesSerializer(serializers.ModelSerializer):
    project_id = serializers.PrimaryKeyRelatedField(
        source='project',
        queryset=Project.objects.all(),
        required=True,
        write_only=True
    )
    
    class Meta:
        model = Comporomises
        fields = ["id", "compromised_CIA_part", "threat_scenario", "component", "project", "project_id"]
        extra_kwargs = {
            'compromised_CIA_part': {'max_length': 100},
            'project': {'read_only': True}
        }