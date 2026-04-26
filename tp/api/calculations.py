from .models import ImpactRating


IMPACT_LABELS = {
    ImpactRating.NEGLIGIBLE: 'Negligible',
    ImpactRating.MODERATE: 'Moderate',
    ImpactRating.MAJOR: 'Major',
    ImpactRating.SEVERE: 'Severe',
}


RISK_LEVEL_MATRIX = {
    ImpactRating.NEGLIGIBLE: {
        1: 1,
        2: 1,
        3: 1,
        4: 1,
        5: 1,
    },
    ImpactRating.MODERATE: {
        1: 1,
        2: 1,
        3: 2,
        4: 2,
        5: 3,
    },
    ImpactRating.MAJOR: {
        1: 1,
        2: 2,
        3: 3,
        4: 3,
        5: 4,
    },
    ImpactRating.SEVERE: {
        1: 2,
        2: 3,
        3: 4,
        4: 5,
        5: 5,
    },
}


def calculate_attack_potential_points(item):
    if item.fr_et >= 99 or item.fr_WoO >= 99:
        return None

    return item.fr_et + item.fr_se + item.fr_koC + item.fr_WoO + item.fr_eq


def calculate_attack_feasibility(item):
    points = calculate_attack_potential_points(item)

    if points is None:
        return {
            'attack_potential_points': None,
            'attack_potential': 'Beyond High',
            'afl': 'Very Low',
            'afl_value': 1,
        }

    if points <= 9:
        return {
            'attack_potential_points': points,
            'attack_potential': 'Basic',
            'afl': 'High',
            'afl_value': 5,
        }

    if points <= 13:
        return {
            'attack_potential_points': points,
            'attack_potential': 'Enhanced-Basic',
            'afl': 'High',
            'afl_value': 4,
        }

    if points <= 19:
        return {
            'attack_potential_points': points,
            'attack_potential': 'Moderate',
            'afl': 'Medium',
            'afl_value': 3,
        }

    if points <= 24:
        return {
            'attack_potential_points': points,
            'attack_potential': 'High',
            'afl': 'Low',
            'afl_value': 2,
        }

    return {
        'attack_potential_points': points,
        'attack_potential': 'Beyond High',
        'afl': 'Very Low',
        'afl_value': 1,
    }


def calculate_impact_level(damage_scenario):
    return max(
        damage_scenario.safety_impact,
        damage_scenario.finantial_impact,
        damage_scenario.operational_impact,
        damage_scenario.privacy_impact,
    )


def impact_level_label(impact_level):
    return IMPACT_LABELS.get(impact_level, str(impact_level))


def best_attack_feasibility_for_threat_scenario(threat_scenario):
    attack_steps = list(threat_scenario.attack_steps.all())
    if not attack_steps:
        return {
            'attack_potential_points': None,
            'attack_potential': None,
            'afl': None,
            'afl_value': None,
        }

    ratings = [calculate_attack_feasibility(attack_step) for attack_step in attack_steps]
    return max(
        ratings,
        key=lambda rating: (
            rating['afl_value'],
            -1 if rating['attack_potential_points'] is None else -rating['attack_potential_points'],
        ),
    )


def calculate_risk_level(impact_level, afl_value):
    if afl_value is None:
        return None

    return RISK_LEVEL_MATRIX.get(impact_level, {}).get(afl_value)
