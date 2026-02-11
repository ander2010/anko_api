from django.urls import path, include
from django.views.decorators.csrf import csrf_exempt
from rest_framework.routers import DefaultRouter

from .views import (
    AccessRequestViewSet, AuthViewSet, FrontendPasswordResetView, PublicBatteryViewSet, PublicDeckViewSet, RBACViewSet, SupportRequestViewSet, UserViewSet, ProjectViewSet, DocumentViewSet, 
    SectionViewSet, TopicViewSet, RuleViewSet, BatteryViewSet,
    ResourceViewSet, PermissionViewSet, RoleViewSet,
    PlanViewSet, PlanLimitViewSet, SubscriptionViewSet,
    BatteryShareViewSet, SavedBatteryViewSet, InviteViewSet,
    DeckViewSet, FlashcardViewSet, DeckShareViewSet, SavedDeckViewSet,GoogleLoginView, FacebookLoginView
)
from dj_rest_auth.views import PasswordResetView, PasswordResetConfirmView


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
router.register(r"public/batteries", PublicBatteryViewSet, basename="public-batteries")
router.register(r"public/decks", PublicDeckViewSet, basename="public-decks")
router.register(r"access-requests", AccessRequestViewSet, basename="access-requests")
# opcional
# router.register(r"tags", TagViewSet, basename="tags")
# router.register(r"qa-pairs", QaPairViewSet, basename="qa-pairs")

router.register(r"support-requests", SupportRequestViewSet, basename="support-request")
urlpatterns = [
    path("auth/google/", GoogleLoginView.as_view(), name="google_login"),
    path("auth/facebook/", FacebookLoginView.as_view(), name="facebook_login"),
    path("auth/password-reset/", csrf_exempt(FrontendPasswordResetView.as_view()), name="password_reset"),


 
    path(
        "auth/password-reset-confirm/<uidb64>/<token>/",
        PasswordResetConfirmView.as_view(),
        name="password_reset_confirm",
    ),


    path(
        "auth/password-reset-confirm/",
        PasswordResetConfirmView.as_view(),
        name="password_reset_confirm_post",
    ),
    path('', include(router.urls)),
]
