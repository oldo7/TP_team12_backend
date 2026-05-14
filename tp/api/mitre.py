import json
import urllib.request
from django.core.cache import cache
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication

MITRE_ICS_URL = 'https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json'
CACHE_KEY = 'mitre_ics_bundle'
CACHE_TIMEOUT = 86400  # 24 hours


def _fetch_bundle():
    bundle = cache.get(CACHE_KEY)
    if bundle is not None:
        return bundle
    with urllib.request.urlopen(MITRE_ICS_URL, timeout=15) as response:
        bundle = json.loads(response.read())
    cache.set(CACHE_KEY, bundle, CACHE_TIMEOUT)
    return bundle


class MitreTacticsView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            bundle = _fetch_bundle()
        except Exception as e:
            return Response({'error': str(e)}, status=502)

        tactics = []
        for obj in bundle.get('objects', []):
            if obj.get('type') != 'x-mitre-tactic':
                continue
            refs = obj.get('external_references', [])
            ext_id = next(
                (r['external_id'] for r in refs if r.get('source_name') == 'mitre-attack'),
                None
            )
            if ext_id:
                tactics.append({'id': ext_id, 'name': obj['name']})

        tactics.sort(key=lambda t: t['id'])
        return Response(tactics)


class MitreTechniquesView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            bundle = _fetch_bundle()
        except Exception as e:
            return Response({'error': str(e)}, status=502)

        techniques = []
        for obj in bundle.get('objects', []):
            if obj.get('type') != 'attack-pattern':
                continue
            if obj.get('x_mitre_deprecated') or obj.get('revoked'):
                continue
            refs = obj.get('external_references', [])
            ext_id = next(
                (r['external_id'] for r in refs if r.get('source_name') == 'mitre-attack'),
                None
            )
            if not ext_id:
                continue
            phases = obj.get('kill_chain_phases', [])
            tactic_short_names = [
                p['phase_name'] for p in phases
                if p.get('kill_chain_name') == 'mitre-attack'
            ]
            techniques.append({'id': ext_id, 'name': obj['name'], 'tactic_short_names': tactic_short_names})

        techniques.sort(key=lambda t: t['id'])
        return Response(techniques)
