from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    AuthViewSet, RBACViewSet, UserViewSet, ProjectViewSet, DocumentViewSet, 
    SectionViewSet, TopicViewSet, RuleViewSet, BatteryViewSet,
    ResourceViewSet, PermissionViewSet, RoleViewSet,
    PlanViewSet, PlanLimitViewSet, SubscriptionViewSet,
    BatteryShareViewSet, SavedBatteryViewSet, InviteViewSet,
    DeckViewSet, FlashcardViewSet, DeckShareViewSet, SavedDeckViewSet
)

router = DefaultRouter()
router.register(r'auth', AuthViewSet, basename='auth')
router.register(r'users', UserViewSet)
router.register(r"projects", ProjectViewSet, basename="projects")

router.register(r'documents', DocumentViewSet)
router.register(r'sections', SectionViewSet)
router.register(r'topics', TopicViewSet, basename="topics")
router.register(r'rules', RuleViewSet, basename="rules")
router.register(r'batteries', BatteryViewSet, basename="batteries")

router.register(r"resources", ResourceViewSet)
router.register(r"permissions", PermissionViewSet)
router.register(r"roles", RoleViewSet)

router.register(r"plans", PlanViewSet)
router.register(r"plan-limits", PlanLimitViewSet)
router.register(r"subscriptions", SubscriptionViewSet)

router.register(r"battery-shares", BatteryShareViewSet)
router.register(r"saved-batteries", SavedBatteryViewSet)
router.register(r"invites", InviteViewSet)

router.register(r"decks", DeckViewSet)
router.register(r"flashcards", FlashcardViewSet)
router.register(r"deck-shares", DeckShareViewSet)
router.register(r"saved-decks", SavedDeckViewSet)
router.register(r"rbac", RBACViewSet, basename="rbac")
# opcional
# router.register(r"tags", TagViewSet, basename="tags")
# router.register(r"qa-pairs", QaPairViewSet, basename="qa-pairs")


urlpatterns = [
    path('', include(router.urls)),
]
