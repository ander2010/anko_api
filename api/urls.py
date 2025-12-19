from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    AuthViewSet, UserViewSet, ProjectViewSet, DocumentViewSet, 
    SectionViewSet, TopicViewSet, RuleViewSet, BatteryViewSet
)

router = DefaultRouter()
router.register(r'auth', AuthViewSet, basename='auth')
router.register(r'users', UserViewSet)
router.register(r'projects', ProjectViewSet)
router.register(r'documents', DocumentViewSet)
router.register(r'sections', SectionViewSet)
router.register(r'topics', TopicViewSet)
router.register(r'rules', RuleViewSet)
router.register(r'batteries', BatteryViewSet)

urlpatterns = [
    path('', include(router.urls)),
]
