from django.db import models

# Create your models here.
class Node(models.Model):
    title = models.CharField(max_length=100)
    content = models.TextField()

    def __str__(self):
        return self.title
    
class Technology(models.Model):
    name = models.CharField()
    description = models.CharField()
class Component(models.Model):
    name = models.CharField()
    description = models.CharField()
    communicates_with = models.ManyToManyField('self', symmetrical=True, blank=True)
    technology = models.ManyToManyField(Technology)
    
class DataEntity(models.Model):
    name = models.CharField()
    description = models.CharField()
    component = models.ForeignKey(Component, null=True, on_delete=models.SET_NULL)
    technology = models.ManyToManyField(Technology)

class Control(models.Model):
    name = models.CharField()
    fr_et = models.CharField()
    fr_se = models.CharField()
    fr_koC = models.CharField()
    fr_WoO = models.CharField()
    fr_eq = models.CharField()
    component = models.ForeignKey(Component, null=True, on_delete=models.SET_NULL)

class ThreatClass(models.Model):
    name = models.CharField()
    description = models.CharField()
class AttackStep(models.Model):
    name = models.CharField()
    fr_et = models.CharField()
    fr_se = models.CharField()
    fr_koC = models.CharField()
    fr_WoO = models.CharField()
    fr_eq = models.CharField()
    component = models.ForeignKey(Component, null=True, on_delete=models.SET_NULL)
    control = models.ManyToManyField(Control)
    prepared_by = models.ManyToManyField('self', symmetrical=True, blank=True)
    threat_class = models.ForeignKey(ThreatClass, null=True, on_delete=models.SET_NULL)

class ThreatScenario(models.Model):
    name = models.CharField()
    attackStep = models.ForeignKey(AttackStep, null=True, on_delete=models.SET_NULL)
    threat_class = models.ForeignKey(ThreatClass, null=True, on_delete=models.SET_NULL)

class DamageScenario(models.Model):
    name = models.CharField()
    affected_CIA_parts = models.JSONField()
    impact_scale = models.CharField()
    safety_impact = models.CharField()
    finantial_impact = models.CharField()
    operational_impact = models.CharField()
    privacy_impact = models.CharField()
    component = models.ForeignKey(Component, null=True, on_delete=models.SET_NULL)
    threat_scenario = models.ForeignKey(ThreatScenario, null=True, on_delete=models.SET_NULL)

class Comporomises(models.Model):
    compromised_CIA_part = models.CharField()
    threat_scenario = models.ForeignKey(ThreatScenario, null=True, on_delete=models.SET_NULL)
    component = models.ForeignKey(Component, null=True, on_delete=models.SET_NULL)