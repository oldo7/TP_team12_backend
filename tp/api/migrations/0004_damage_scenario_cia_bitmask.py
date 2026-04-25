from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import migrations, models


CIA_MAP = {
    '': 0,
    '0': 0,
    '000': 0,
    'none': 0,
    'availability': 1,
    'a': 1,
    '1': 1,
    '001': 1,
    'integrity': 2,
    'i': 2,
    '2': 2,
    '010': 2,
    'confidentiality': 4,
    'c': 4,
    '4': 4,
    '100': 4,
    'ia': 3,
    '011': 3,
    'ca': 5,
    '101': 5,
    'ci': 6,
    '110': 6,
    'cia': 7,
    'all': 7,
    '111': 7,
}


def normalize_cia_bitmask(apps, schema_editor):
    DamageScenario = apps.get_model('api', 'DamageScenario')

    for obj in DamageScenario.objects.all():
        normalized = str(obj.affected_CIA_parts).strip().lower().replace(',', '').replace(' ', '')
        if normalized not in CIA_MAP:
            raise ValueError(
                f'Unsupported legacy value for DamageScenario.affected_CIA_parts: {obj.affected_CIA_parts!r}'
            )
        obj.affected_CIA_parts = str(CIA_MAP[normalized])
        obj.save(update_fields=['affected_CIA_parts'])


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0003_rating_choice_fields'),
    ]

    operations = [
        migrations.RunPython(normalize_cia_bitmask, migrations.RunPython.noop),
        migrations.AlterField(
            model_name='damagescenario',
            name='affected_CIA_parts',
            field=models.PositiveSmallIntegerField(
                default=0,
                validators=[MinValueValidator(0), MaxValueValidator(7)],
            ),
        ),
    ]
