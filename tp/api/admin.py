from django.contrib import admin

# Register your models here.
from .models import *
admin.site.register(Node)
admin.site.register(Technology)
admin.site.register(Component)
admin.site.register(DataEntity)
admin.site.register(Control)
admin.site.register(ThreatClass)
admin.site.register(AttackStep)
admin.site.register(ThreatScenario)
admin.site.register(DamageScenario)
admin.site.register(Comporomises)