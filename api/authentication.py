from rest_framework.authentication import TokenAuthentication


class TokenAuthWithRequestUser(TokenAuthentication):
    """
    Token auth that also writes the authenticated user to the underlying HttpRequest
    so middleware logging can see it after the response.
    """

    def authenticate(self, request):
        result = super().authenticate(request)
        if result:
            user, auth = result
            try:
                # Expose to Django middleware/logs
                request._request.user = user
                request._request.auth = auth
            except Exception:
                pass
        return result
