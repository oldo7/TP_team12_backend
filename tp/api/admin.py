from django.contrib import admin
from .models import *

@admin.register(Component)
class ComponentAdmin(admin.ModelAdmin):
    list_display = ['id', 'name', 'description']
    filter_horizontal = ['technology', 'communicates_with']

@admin.register(DamageScenario)
class DamageScenarioAdmin(admin.ModelAdmin):
    list_display = ['id', 'name', 'component', 'threat_scenario']
    list_filter = ['component', 'threat_scenario']

@admin.register(Control)
class ControlAdmin(admin.ModelAdmin):
    list_display = ['id', 'name', 'component']
    list_filter = ['component']
    filter_horizontal = ['attack_steps']

@admin.register(AttackStep)
class AttackStepAdmin(admin.ModelAdmin):
    list_display = ['id', 'name', 'component', 'threat_class']
    list_filter = ['component', 'threat_class']
    filter_horizontal = ['prepared_by', 'threat_scenario', 'controls']

@admin.register(ThreatScenario)
class ThreatScenarioAdmin(admin.ModelAdmin):
    list_display = ['id', 'name', 'threat_class']
    list_filter = ['threat_class']
    filter_horizontal = ['attack_step', 'damage_scenario']

@admin.register(Technology)
class TechnologyAdmin(admin.ModelAdmin):
    list_display = ['id', 'name', 'description']

@admin.register(DataEntity)
class DataEntityAdmin(admin.ModelAdmin):
    list_display = ['id', 'name', 'description', 'component']
    list_filter = ['component']
    filter_horizontal = ['technology']

@admin.register(ThreatClass)
class ThreatClassAdmin(admin.ModelAdmin):
    list_display = ['id', 'name', 'description']

@admin.register(Comporomises)
class ComporomisesAdmin(admin.ModelAdmin):
    list_display = ['id', 'component', 'threat_scenario', 'compromised_CIA_part']
    list_filter = ['component', 'threat_scenario']

@admin.register(Node)
class NodeAdmin(admin.ModelAdmin):
    list_display = ['id', 'title']