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


def normalize_compromise_cia_bitmask(apps, schema_editor):
    Comporomises = apps.get_model('api', 'Comporomises')

    for obj in Comporomises.objects.all():
        normalized = str(obj.compromised_CIA_part).strip().lower().replace(',', '').replace(' ', '')
        if normalized not in CIA_MAP:
            raise ValueError(
                f'Unsupported legacy value for Comporomises.compromised_CIA_part: {obj.compromised_CIA_part!r}'
            )
        obj.compromised_CIA_part = str(CIA_MAP[normalized])
        obj.save(update_fields=['compromised_CIA_part'])


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0004_damage_scenario_cia_bitmask'),
    ]

    operations = [
        migrations.RunPython(normalize_compromise_cia_bitmask, migrations.RunPython.noop),
        migrations.AlterField(
            model_name='comporomises',
            name='compromised_CIA_part',
            field=models.PositiveSmallIntegerField(
                default=0,
                validators=[MinValueValidator(0), MaxValueValidator(7)],
            ),
        ),
    ]
