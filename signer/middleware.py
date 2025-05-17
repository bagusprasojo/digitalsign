from django.http import JsonResponse
from signer.models import ApiClient

class ApiKeyMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        api_key = request.headers.get('X-API-KEY')
        if request.path.startswith('/api/') and not ApiClient.objects.filter(api_key=api_key, is_active=True).exists():
            return JsonResponse({'error': 'Invalid or missing API key'}, status=401)
        return self.get_response(request)
