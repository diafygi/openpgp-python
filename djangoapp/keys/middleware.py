from django.contrib.auth import login
from django.contrib.auth.models import User

class ReadOnlyMiddleware(object):
    def process_request(self, request):
        if not request.user.is_authenticated() and \
          not request.path.startswith("/login") and \
          not request.path.startswith("/logout"):
            user = User.objects.get(username="readonly")
            user.backend = "django.contrib.auth.backends.ModelBackend"
            login(request, user)
        return None

