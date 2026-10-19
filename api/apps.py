from django.apps import AppConfig


class ApiConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'api'
    def ready(self):
        
        import api.signals
        import api.checks  # noqa: F401  (C3/C7 deploy checks)  
