from corehq.apps.auth_providers.utils import SessionAuthManager


class SessionAuthManagerMiddleware:
    def process_request(self, request):
        request.auth_manager = SessionAuthManager(request)
