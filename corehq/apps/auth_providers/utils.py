from typing import Dict, Callable

from django.http import HttpRequest


class SessionAuthManager(object):
    def __init__(self, request):
        self.request = request

    def authenticate(self, auth_provider_id, auth_data=None):
        self._initialize_session_properties()
        self.request.session[AUTH_PROVIDERS][auth_provider_id] = auth_data or {}
        self.request.session.modified = True

    def revoke_auth(self, auth_provider_id):
        self._initialize_session_properties()
        del self.request.session[AUTH_PROVIDERS][auth_provider_id]
        self.request.session.modified = True

    def is_authorized(self, authorization_map):
        return bool(self.get_authorized_authentications(authorization_map))

    def get_authorized_authentications(self, authorization_map: Dict[str, Callable[[HttpRequest], bool]]):
        """
        authorization_map says which auth_providers are accepted and on what condition.
        This would come from a project's or enterprise account's configuration of acceptable auth.
        It is a {auth_provider_id: matcher} map,
        where matcher is a callable that takes in a request
        returns whether this auth provider constitutes acceptable authorization for this request.

        Having {..., auth_provider_id: (lambda request: False), ...} yields the same behavior
        as omitting auth_provider_id from the map.

        For example, if an enterprise requires all of its employees to use its single-sign-on provider ('AD__123')
        but non-employees who are given access can use normal CommCare password login ('CC'), it might have
        authorization_map={
            'CC': lambda request: request.user.username.split('@')[-1] != 'examplecorp.org',
            'AD__123': lambda request: request.user.username.split('@')[-1] == 'examplecorp.org',
        }
        """
        return {
            auth_provider_id: self.request.session[AUTH_PROVIDERS][auth_provider_id]
            for auth_provider_id, matcher in authorization_map.items()
            if auth_provider_id in self.request.session[AUTH_PROVIDERS]
            and matcher(self.request, self.request.session[AUTH_PROVIDERS][auth_provider_id])
        }

    def _initialize_session_properties(self):
        if 'auth_providers' not in self.request.session:
            self.request.session['auth_providers'] = {}
            self.request.session.modified = True


AUTH_PROVIDERS = 'auth_providers'
