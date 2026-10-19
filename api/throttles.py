from rest_framework.throttling import AnonRateThrottle, UserRateThrottle


class BurstAnonRateThrottle(AnonRateThrottle):
    scope = "anon_burst"


class SustainedAnonRateThrottle(AnonRateThrottle):
    scope = "anon_sustained"


class BurstUserRateThrottle(UserRateThrottle):
    scope = "user_burst"


class SustainedUserRateThrottle(UserRateThrottle):
    scope = "user_sustained"


class LeadAnonRateThrottle(AnonRateThrottle):
    """Caps anonymous lead submissions (public landing forms) per IP."""
    scope = "anon_lead"


# ---------------------------------------------------------------------------
# C3: scoped limits for sensitive / expensive endpoints. A per-view
# throttle_classes list replaces the global defaults, so these are always used
# together with them (see with_default_throttles).
# ---------------------------------------------------------------------------

class AuthAnonRateThrottle(AnonRateThrottle):
    """Login, registration, password reset and e-mail verification, per IP."""
    scope = "auth"


class InvitationUserRateThrottle(UserRateThrottle):
    """Sending / resending company invitations, per user."""
    scope = "invitations"


class AIGenerationUserRateThrottle(UserRateThrottle):
    """AI generation requests (decks, batteries, auto-generate, graph rebuild), per user."""
    scope = "ai_generation"


def with_default_throttles(*extra):
    from rest_framework.settings import api_settings
    return [*api_settings.DEFAULT_THROTTLE_CLASSES, *extra]
