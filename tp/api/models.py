from django.db import models

class Node(models.Model):
    title = models.CharField(max_length=100)
    content = models.TextField()

    def __str__(self):
        return self.title
    
class Technology(models.Model):
    name = models.CharField(max_length=100)
    description = models.CharField(max_length=500)

    def __str__(self):
        return self.name
    
class Component(models.Model):
    name = models.CharField(max_length=100)
    description = models.CharField(max_length=500)
    communicates_with = models.ManyToManyField('self', symmetrical=True, blank=True)
    technology = models.ManyToManyField(Technology, blank=True)

    def __str__(self):
        return self.name
    
class DataEntity(models.Model):
    name = models.CharField(max_length=100)
    description = models.CharField(max_length=500)
    component = models.ForeignKey(Component, null=True, blank=True, on_delete=models.SET_NULL, related_name='data_entities')
    technology = models.ManyToManyField(Technology, blank=True)

    def __str__(self):
        return self.name

class Control(models.Model):
    name = models.CharField(max_length=100)
    fr_et = models.CharField(max_length=100)
    fr_se = models.CharField(max_length=100)
    fr_koC = models.CharField(max_length=100)
    fr_WoO = models.CharField(max_length=100)
    fr_eq = models.CharField(max_length=100)
    component = models.ForeignKey(Component, null=True, blank=True, on_delete=models.SET_NULL, related_name='controls')
    attack_steps = models.ManyToManyField('AttackStep', blank=True)

    def __str__(self):
        return self.name

class ThreatClass(models.Model):
    name = models.CharField(max_length=100)
    description = models.CharField(max_length=500)

    def __str__(self):
        return self.name
    
class AttackStep(models.Model):
    name = models.CharField(max_length=100)
    fr_et = models.CharField(max_length=100)
    fr_se = models.CharField(max_length=100)
    fr_koC = models.CharField(max_length=100)
    fr_WoO = models.CharField(max_length=100)
    fr_eq = models.CharField(max_length=100)
    component = models.ForeignKey(Component, null=True, blank=True, on_delete=models.SET_NULL, related_name='attack_steps')
    prepared_by = models.ManyToManyField('self', symmetrical=True, blank=True)
    threat_class = models.ForeignKey(ThreatClass, null=True, blank=True, on_delete=models.SET_NULL)
    threat_scenario = models.ManyToManyField('ThreatScenario', blank=True)
    controls = models.ManyToManyField(Control, blank=True)

    def __str__(self):
        return self.name

class ThreatScenario(models.Model):
    name = models.CharField(max_length=100)
    attack_step = models.ManyToManyField(AttackStep, blank=True)
    threat_class = models.ForeignKey(ThreatClass, null=True, blank=True, on_delete=models.SET_NULL)
    damage_scenario = models.ManyToManyField('DamageScenario', blank=True)

    def __str__(self):
        return self.name

class DamageScenario(models.Model):
    name = models.CharField(max_length=100)
    affected_CIA_parts = models.CharField(max_length=100, blank=True)
    impact_scale = models.CharField(max_length=50)
    safety_impact = models.CharField(max_length=100)
    finantial_impact = models.CharField(max_length=100)
    operational_impact = models.CharField(max_length=100)
    privacy_impact = models.CharField(max_length=100)
    component = models.ForeignKey(Component, null=True, blank=True, on_delete=models.SET_NULL, related_name='damage_scenarios')
    threat_scenario = models.ForeignKey(ThreatScenario, null=True, blank=True, on_delete=models.SET_NULL)

    def __str__(self):
        return self.name

class Comporomises(models.Model):
    compromised_CIA_part = models.CharField(max_length=100)
    threat_scenario = models.ForeignKey(ThreatScenario, null=True, blank=True, on_delete=models.SET_NULL)
    component = models.ForeignKey(Component, null=True, blank=True, on_delete=models.SET_NULL)

    def __str__(self):
        return f"{self.component} - {self.compromised_CIA_part}"