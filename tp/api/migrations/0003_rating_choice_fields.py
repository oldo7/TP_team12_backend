from django.db import migrations, models


IMPACT_MAP = {
    '0': 0,
    'negligible': 0,
    'low': 0,
    '1': 1,
    'moderate': 1,
    'medium': 1,
    '2': 2,
    'major': 2,
    'high': 2,
    '3': 3,
    'severe': 3,
    'critical': 3,
}

ET_MAP = {
    '0': 0,
    '<=1 day': 0,
    'low': 0,
    '1': 1,
    '<=1 week': 1,
    '4': 4,
    '<=1 month': 4,
    'medium': 4,
    '10': 10,
    '<=3 months': 10,
    'high': 10,
    '17': 17,
    '<=6 months': 17,
    '19': 19,
    '>6 months': 19,
    'critical': 19,
    '99': 99,
    'not practical': 99,
}

SE_MAP = {
    '0': 0,
    'layman': 0,
    'low': 0,
    '3': 3,
    'proficient': 3,
    'medium': 3,
    '6': 6,
    'expert': 6,
    'high': 6,
    '8': 8,
    'multiple experts': 8,
    'critical': 8,
}

KOC_MAP = {
    '0': 0,
    'public': 0,
    'low': 0,
    '3': 3,
    'restricted': 3,
    'medium': 3,
    '7': 7,
    'sensitive': 7,
    'high': 7,
    '11': 11,
    'critical': 11,
}

WOO_MAP = {
    '0': 0,
    'unnecessary/unlimited': 0,
    'low': 0,
    '1': 1,
    'easy': 1,
    '4': 4,
    'moderate': 4,
    'medium': 4,
    '10': 10,
    'difficult': 10,
    'high': 10,
    '99': 99,
    'none': 99,
}

EQ_MAP = {
    '0': 0,
    'standard': 0,
    'low': 0,
    '4': 4,
    'specialized': 4,
    'medium': 4,
    '7': 7,
    'bespoke': 7,
    'high': 7,
    '9': 9,
    'multiple bespoke': 9,
    'critical': 9,
}


def normalize_choice(value, mapping, field_name):
    if value is None:
        return None

    normalized = str(value).strip().lower()
    if normalized == '':
        return None
    if normalized not in mapping:
        raise ValueError(f'Unsupported legacy value for {field_name}: {value!r}')
    return str(mapping[normalized])


def normalize_rating_fields(apps, schema_editor):
    AttackStep = apps.get_model('api', 'AttackStep')
    Control = apps.get_model('api', 'Control')
    DamageScenario = apps.get_model('api', 'DamageScenario')

    for model in (AttackStep, Control):
        for obj in model.objects.all():
            obj.fr_et = normalize_choice(obj.fr_et, ET_MAP, f'{model.__name__}.fr_et')
            obj.fr_se = normalize_choice(obj.fr_se, SE_MAP, f'{model.__name__}.fr_se')
            obj.fr_koC = normalize_choice(obj.fr_koC, KOC_MAP, f'{model.__name__}.fr_koC')
            obj.fr_WoO = normalize_choice(obj.fr_WoO, WOO_MAP, f'{model.__name__}.fr_WoO')
            obj.fr_eq = normalize_choice(obj.fr_eq, EQ_MAP, f'{model.__name__}.fr_eq')
            obj.save(update_fields=['fr_et', 'fr_se', 'fr_koC', 'fr_WoO', 'fr_eq'])

    for obj in DamageScenario.objects.all():
        obj.impact_scale = normalize_choice(obj.impact_scale, IMPACT_MAP, 'DamageScenario.impact_scale')
        obj.safety_impact = normalize_choice(obj.safety_impact, IMPACT_MAP, 'DamageScenario.safety_impact')
        obj.finantial_impact = normalize_choice(obj.finantial_impact, IMPACT_MAP, 'DamageScenario.finantial_impact')
        obj.operational_impact = normalize_choice(obj.operational_impact, IMPACT_MAP, 'DamageScenario.operational_impact')
        obj.privacy_impact = normalize_choice(obj.privacy_impact, IMPACT_MAP, 'DamageScenario.privacy_impact')
        obj.save(update_fields=[
            'impact_scale',
            'safety_impact',
            'finantial_impact',
            'operational_impact',
            'privacy_impact',
        ])


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0002_tara_relationship_cleanup'),
    ]

    operations = [
        migrations.RunPython(normalize_rating_fields, migrations.RunPython.noop),
        migrations.AlterField(
            model_name='attackstep',
            name='fr_WoO',
            field=models.PositiveSmallIntegerField(choices=[(0, 'Unnecessary/unlimited'), (1, 'Easy'), (4, 'Moderate'), (10, 'Difficult'), (99, 'None')]),
        ),
        migrations.AlterField(
            model_name='attackstep',
            name='fr_eq',
            field=models.PositiveSmallIntegerField(choices=[(0, 'Standard'), (4, 'Specialized'), (7, 'Bespoke'), (9, 'Multiple bespoke')]),
        ),
        migrations.AlterField(
            model_name='attackstep',
            name='fr_et',
            field=models.PositiveSmallIntegerField(choices=[(0, '<=1 day'), (1, '<=1 week'), (4, '<=1 month'), (10, '<=3 months'), (17, '<=6 months'), (19, '>6 months'), (99, 'Not practical')]),
        ),
        migrations.AlterField(
            model_name='attackstep',
            name='fr_koC',
            field=models.PositiveSmallIntegerField(choices=[(0, 'Public'), (3, 'Restricted'), (7, 'Sensitive'), (11, 'Critical')]),
        ),
        migrations.AlterField(
            model_name='attackstep',
            name='fr_se',
            field=models.PositiveSmallIntegerField(choices=[(0, 'Layman'), (3, 'Proficient'), (6, 'Expert'), (8, 'Multiple experts')]),
        ),
        migrations.AlterField(
            model_name='control',
            name='fr_WoO',
            field=models.PositiveSmallIntegerField(choices=[(0, 'Unnecessary/unlimited'), (1, 'Easy'), (4, 'Moderate'), (10, 'Difficult'), (99, 'None')]),
        ),
        migrations.AlterField(
            model_name='control',
            name='fr_eq',
            field=models.PositiveSmallIntegerField(choices=[(0, 'Standard'), (4, 'Specialized'), (7, 'Bespoke'), (9, 'Multiple bespoke')]),
        ),
        migrations.AlterField(
            model_name='control',
            name='fr_et',
            field=models.PositiveSmallIntegerField(choices=[(0, '<=1 day'), (1, '<=1 week'), (4, '<=1 month'), (10, '<=3 months'), (17, '<=6 months'), (19, '>6 months'), (99, 'Not practical')]),
        ),
        migrations.AlterField(
            model_name='control',
            name='fr_koC',
            field=models.PositiveSmallIntegerField(choices=[(0, 'Public'), (3, 'Restricted'), (7, 'Sensitive'), (11, 'Critical')]),
        ),
        migrations.AlterField(
            model_name='control',
            name='fr_se',
            field=models.PositiveSmallIntegerField(choices=[(0, 'Layman'), (3, 'Proficient'), (6, 'Expert'), (8, 'Multiple experts')]),
        ),
        migrations.AlterField(
            model_name='damagescenario',
            name='finantial_impact',
            field=models.PositiveSmallIntegerField(choices=[(0, 'Negligible'), (1, 'Moderate'), (2, 'Major'), (3, 'Severe')]),
        ),
        migrations.AlterField(
            model_name='damagescenario',
            name='impact_scale',
            field=models.PositiveSmallIntegerField(choices=[(0, 'Negligible'), (1, 'Moderate'), (2, 'Major'), (3, 'Severe')]),
        ),
        migrations.AlterField(
            model_name='damagescenario',
            name='operational_impact',
            field=models.PositiveSmallIntegerField(choices=[(0, 'Negligible'), (1, 'Moderate'), (2, 'Major'), (3, 'Severe')]),
        ),
        migrations.AlterField(
            model_name='damagescenario',
            name='privacy_impact',
            field=models.PositiveSmallIntegerField(choices=[(0, 'Negligible'), (1, 'Moderate'), (2, 'Major'), (3, 'Severe')]),
        ),
        migrations.AlterField(
            model_name='damagescenario',
            name='safety_impact',
            field=models.PositiveSmallIntegerField(choices=[(0, 'Negligible'), (1, 'Moderate'), (2, 'Major'), (3, 'Severe')]),
        ),
    ]
