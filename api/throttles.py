from rest_framework.throttling import AnonRateThrottle, UserRateThrottle


class BurstAnonRateThrottle(AnonRateThrottle):
    scope = "anon_burst"


class SustainedAnonRateThrottle(AnonRateThrottle):
    scope = "anon_sustained"


class BurstUserRateThrottle(UserRateThrottle):
    scope = "user_burst"


class SustainedUserRateThrottle(UserRateThrottle):
    scope = "user_sustained"
