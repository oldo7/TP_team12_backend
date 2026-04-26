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


def calculate_effective_attack_feasibility(attack_step, active_controls):
    """
    Compute accumulated AFL for an attack step with a specific set of active controls.
    Each control's fr_* values are added to the attack step's base values.
    If either the base attack step or any active control has fr_et/fr_WoO == 99,
    the accumulated result is also 'Not practical' → Very Low AFL.
    active_controls: iterable of Control objects belonging to the active control group.
    """
    relevant = [c for c in active_controls if attack_step in c.attack_steps.all()]

    base_et  = attack_step.fr_et
    base_se  = attack_step.fr_se
    base_koc = attack_step.fr_koC
    base_woo = attack_step.fr_WoO
    base_eq  = attack_step.fr_eq

    delta_et  = sum(c.fr_et  for c in relevant)
    delta_se  = sum(c.fr_se  for c in relevant)
    delta_koc = sum(c.fr_koC for c in relevant)
    delta_woo = sum(c.fr_WoO for c in relevant)
    delta_eq  = sum(c.fr_eq  for c in relevant)

    acc_et  = base_et  + delta_et
    acc_se  = base_se  + delta_se
    acc_koc = base_koc + delta_koc
    acc_woo = base_woo + delta_woo
    acc_eq  = base_eq  + delta_eq

    if acc_et >= 99 or acc_woo >= 99:
        return {
            'attack_potential_points': None,
            'attack_potential': 'Beyond High',
            'afl': 'Very Low',
            'afl_value': 1,
        }

    points = acc_et + acc_se + acc_koc + acc_woo + acc_eq

    if points <= 9:
        ap, afl, afl_value = 'Basic', 'High', 5
    elif points <= 13:
        ap, afl, afl_value = 'Enhanced-Basic', 'High', 4
    elif points <= 19:
        ap, afl, afl_value = 'Moderate', 'Medium', 3
    elif points <= 24:
        ap, afl, afl_value = 'High', 'Low', 2
    else:
        ap, afl, afl_value = 'Beyond High', 'Very Low', 1

    return {
        'attack_potential_points': points,
        'attack_potential': ap,
        'afl': afl,
        'afl_value': afl_value,
    }


def _rating_key(r):
    """Higher = more feasible for attacker. Used to compare / pick best path."""
    av = r['afl_value'] or 0
    pts = r['attack_potential_points']
    # prefer higher afl_value; within same level, fewer points = easier
    return (av, -pts if pts is not None else float('inf'))


def _find_all_paths(attack_steps):
    """
    Enumerate all root-to-leaf paths in the attack step DAG, scoped to the
    given list of steps.  Returns a list of lists of step objects.
    Falls back to one path per step when no ordering is defined (no previous_steps).
    """
    if not attack_steps:
        return []

    step_ids = {s.id for s in attack_steps}
    step_map = {s.id: s for s in attack_steps}

    predecessors = {s.id: set() for s in attack_steps}
    successors   = {s.id: set() for s in attack_steps}

    for step in attack_steps:
        for prev in step.previous_steps.all():
            if prev.id in step_ids:
                predecessors[step.id].add(prev.id)
                successors[prev.id].add(step.id)

    roots = [s for s in attack_steps if not predecessors[s.id]]
    if not roots:
        # Cycle or fully disconnected — treat each step independently
        return [[s] for s in attack_steps]

    all_paths = []

    def dfs(step_id, path, visited):
        if step_id in visited:
            return
        visited = visited | {step_id}
        path = path + [step_map[step_id]]
        children = successors[step_id] - visited
        if not children:
            all_paths.append(path)
        else:
            for child_id in children:
                dfs(child_id, path, visited)

    for root in roots:
        dfs(root.id, [], set())

    return all_paths or [[s] for s in attack_steps]


def best_attack_feasibility_for_threat_scenario(threat_scenario):
    attack_steps = list(threat_scenario.attack_steps.all())
    if not attack_steps:
        return {
            'attack_potential_points': None,
            'attack_potential': None,
            'afl': None,
            'afl_value': None,
        }

    paths = _find_all_paths(attack_steps)

    # Each path's feasibility is limited by its hardest step (min rating key).
    # The attacker picks the easiest complete path (max over all paths).
    bottlenecks = [
        min([calculate_attack_feasibility(s) for s in path], key=_rating_key)
        for path in paths
    ]
    return max(bottlenecks, key=_rating_key)


def best_effective_attack_feasibility_for_threat_scenario(threat_scenario, active_controls):
    attack_steps = list(threat_scenario.attack_steps.all())
    if not attack_steps:
        return {
            'attack_potential_points': None,
            'attack_potential': None,
            'afl': None,
            'afl_value': None,
        }

    paths = _find_all_paths(attack_steps)

    bottlenecks = [
        min(
            [calculate_effective_attack_feasibility(s, active_controls) for s in path],
            key=_rating_key,
        )
        for path in paths
    ]
    return max(bottlenecks, key=_rating_key)


def calculate_risk_level(impact_level, afl_value):
    if afl_value is None:
        return None

    return RISK_LEVEL_MATRIX.get(impact_level, {}).get(afl_value)
