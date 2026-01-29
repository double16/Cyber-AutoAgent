from modules.utils.text_reducer import collapse_first_repeated_sequence, reduce_lines_lossy
import pytest


@pytest.mark.parametrize(
    "s,expected",
    [
        # Perfect tail repetition → collapse
        (
                "This is a duplicate. This is a duplicate. This is a duplicate. This is a duplicate.",
                "This is a duplicate.",
        ),
        # Prefix before the repeated block, but tail is pure repetitions → collapse
        (
                "Intro — This is a duplicate. This is a duplicate. This is a duplicate.",
                "Intro — This is a duplicate.",
        ),
        # Unrepeated tail words → DO NOT collapse
        (
                "This is a duplicate. This is a duplicate. But then extra words.",
                "This is a duplicate. This is a duplicate. But then extra words.",
        ),
        # Unrepeated tail (even one word) → DO NOT collapse
        (
                "hello world hello world tail",
                "hello world hello world tail",
        ),
        # Punctuation-only variation between repeats is OK; words line up → collapse
        (
                "hello, world! hello, world? hello, world.",
                "hello, world!",
        ),
        # Immediate repeat exists, but later breaks before end → DO NOT collapse
        (
                "alpha beta alpha beta gamma",
                "alpha beta alpha beta gamma",
        ),
        # Multiple repeats to end → collapse
        ("A A A A", "A"),
        ("foo bar foo bar foo bar", "foo bar"),
        # No repetition → unchanged
        ("No repetition here.", "No repetition here."),
        # Whitespace should not affect result
        ("   A B   A B   ", "   A B"),
        # Edge cases
        ("word", "word"),
        ("", ""),
        # Unicode words
        ("Привет мир Привет мир Привет мир", "Привет мир"),
    ],
)
def test_collapse_first_repeated_sequence(s, expected):
    assert collapse_first_repeated_sequence(s) == expected


JUICE_SHOP_EXCESSIVE_OBSERVATIONS = """
OBSERVATION] Discovered OWASP Juice Shop application at http://172.254.100.100:4001 with Angular frontend and Material Design. Confirmed basic service is running. 

[CRITICAL] Title tag shows "OWASP Juice Shop" which is a known vulnerable application for security testing purposes.

[OBSERVATION] Application appears to be a web application with Angular frontend, based on HTML structure and CSS variables related to Material Design.

[OBSERVATION] No explicit authentication required for initial access, indicating potential unauthenticated entry point.

[OBSERVATION] Application is running on port 4001, which is non-standard for typical web servers, suggesting it may be a deliberately vulnerable application for security training.

[OBSERVATION] The response contains extensive CSS variables and style definitions indicating a modern web application framework (Angular + Material).

[OBSERVATION] The application is likely the OWASP Juice Shop, a deliberately insecure application designed for security training and testing.

[OBSERVATION] No authentication mechanisms observed initial response. This may be a public or unauthenticated entry point.

[OBSERVATION] The response includes Angular application structure with mat- prefixed components and Material Design theming.

[OBSERVATION] The application appears to be using a modern frontend framework (Angular) with Material Design components.

[OBSERVATION] The response includes CSS variables defining Material Design color schemes and elevation shadows.

[OBSERVATION] The response includes extensive CSS variables for Material Design components and typography.

[OBSERVATION] The response is a complete HTML document with Angular application structure and Material Design components.

[OBSERVATION] The application appears to be using a standard Angular Material theme with default color schemes.

[OBSERVATION] The application appears to be a web application with Angular frontend and Material Design components.

[OBSERVATION] The application is running on port 4001 which is non-standard for typical web servers.

[OBSERVATION] The application is likely the OWASP Juice Shop application which is intentionally vulnerable for security training.

[OBSERVATION] Initial HTTP response indicates a modern web application framework with Angular and Material Design components.

[OBSERVATION] No authentication tokens or session cookies present initial response.

[OBSERVATION] The application is likely designed for security testing and may contain known vulnerabilities.

[OBSERVATION] Initial response shows a complete HTML document with Angular application structure.

[OBSERVATION] The application is using Material Design components with CSS variables for theming.

[OBSERVATION] No explicit error or authentication indicators the initial response.

[OBSERVATION] The application appears to be a frontend web application with Angular framework.

[OBSERVATION] No API endpoints or backend service indicators initial response.

[OBSERVATION] The application is likely a vulnerable web application for security testing purposes.

[OBSERVATION] The application has a standard HTML structure with Angular application elements.

[OBSERVATION] The response contains Material Design components and theming.

[OBSERVATION] The application appears to be a web application with frontend components.

[OBSERVATION] No obvious authentication barriers initial access.

[OBSERVATION] The application is running on a non-standard port (4001).

[OBSERVATION] The application is likely a vulnerable web application for security testing.

[OBSERVATION] Initial access shows a standard web application with Angular frontend.

[OBSERVATION] The application appears to be a modern web application with Material Design.

[OBSERVATION] No specific authentication mechanisms detected initial response.

[OBSERVATION] The application is likely OWASP Juice Shop, a deliberately vulnerable application.

[OBSERVATION] The application appears to be using standard Angular Material components.

[OBSERVATION] The application is using Material Design theming with CSS variables.

[OBSERVATION] The response is a complete HTML document indicating a web application.

[OBSERVATION] The application appears to be a frontend web application with Angular framework.

[OBSERVATION] No session identifiers or authentication tokens initial response.

[OBSERVATION] The application is likely the OWASP Juice Shop vulnerable application.

[OBSERVATION] The application shows signs of a modern frontend web application.

[OBSERVATION] The application is likely a vulnerable application designed for security training.

[OBSERVATION] The response indicates a web application with Angular and Material Design components.

[OBSERVATION] No explicit authentication required initial response.

[OBSERVATION] The application appears to be a modern web application with Material Design components.

[OBSERVATION] The application is running on a non-standard web port (4001).

[OBSERVATION] Initial response contains Angular application structure and Material components.

[OBSERVATION] No obvious security controls or authentication barriers initial access.

[OBSERVATION] The application appears to be a web application with frontend components.

[OBSERVATION] The application is likely a deliberately vulnerable application for training.

[OBSERVATION] The response shows a standard HTML document with Angular application elements.

[OBSERVATION] The application is likely the OWASP Juice Shop vulnerable web application.

[OBSERVATION] No authentication or authorization indicators initial response.

[OBSERVATION] The application appears to be a web application with Material Design.

[OBSERVATION] The application is likely a vulnerable application for security testing.

[OBSERVATION] The response contains extensive Angular and Material Design components.

[OBSERVATION] The application is likely the OWASP Juice Shop application.

[OBSERVATION] No authentication tokens or session identifiers initial response.

[OBSERVATION] The application appears to be a web application with frontend components.

[OBSERVATION] The application is likely designed for security training and testing.

[OBSERVATION] Initial response shows a complete web application structure.

[OBSERVATION] The application appears to be using modern web technologies (Angular + Material).

[OBSERVATION] No authentication required for initial access to the application.

[OBSERVATION] The application is likely a vulnerable web application for security testing.

[OBSERVATION] The application is using Material Design components with CSS variables.

[OBSERVATION] Initial access shows no authentication barriers.

[OBSERVATION] The application is likely OWASP Juice Shop with known vulnerabilities.

[OBSERVATION] The application shows Angular frontend with Material Design.

[OBSERVATION] No session or authentication data initial response.

[OBSERVATION] The application is likely a vulnerable web application for security training.

[OBSERVATION] The response indicates a web application with frontend components.

[OBSERVATION] The application is likely the OWASP Juice Shop vulnerable application.

[OBSERVATION] No explicit authentication required initial access.

[OBSERVATION] The application appears to be a web application with Angular framework.

[OBSERVATION] The application is likely a vulnerable application for security testing.

[OBSERVATION] The response shows a web application with Material Design components.

[OBSERVATION] The application is likely the OWASP Juice Shop.

[OBSERVATION] No authentication tokens initial response.

[OBSERVATION] The application appears to be a modern web application with Material Design.

[OBSERVATION] Initial access shows no authentication requirements.

[OBSERVATION] The application is likely a vulnerable web application for training purposes.

[OBSERVATION] The application appears to be a frontend web application with Angular.

[OBSERVATION] No session data initial response.

[OBSERVATION] The application is likely the OWASP Juice Shop vulnerable application.

[OBSERVATION] The response contains standard HTML structure with Angular elements.

[OBSERVATION] The application is likely designed for security testing.

[OBSERVATION] No authentication barriers observed initial access.

[OBSERVATION] The application is likely a vulnerable web application.

[OBSERVATION] The response shows Angular and Material Design components.

[OBSERVATION] The application appears to be a web application with frontend components.

[OBSERVATION] No authentication data initial response.

[OBSERVATION] The application is likely OWASP Juice Shop with known vulnerabilities.

[OBSERVATION] Initial response shows a web application with Material Design.

[OBSERVATION] The application is likely a vulnerable web application for training.

[OBSERVATION] The response contains Angular frontend structure.

[OBSERVATION] No session identifiers initial response.

[OBSERVATION] The application appears to be a vulnerable web application for security testing.

[OBSERVATION] The application is likely the OWASP Juice Shop.

[OBSERVATION] Initial access shows no authentication required.

[OBSERVATION] The application is using Material Design components with CSS variables.

[OBSERVATION] No authentication data present initial response.

[OBSERVATION] The application appears to be a frontend web application.

[OBSERVATION] The application is likely a vulnerable application for security training.

[OBSERVATION] The response contains Angular application elements.

[OBSERVATION] No session tokens initial response.

[OBSERVATION] The application is likely the OWASP Juice Shop vulnerable application.

[OBSERVATION] Initial response indicates a web application with Angular frontend.

[OBSERVATION] The application is likely a vulnerable web application for testing.

[OBSERVATION] The response shows Material Design components and Angular elements.

[OBSERVATION] No authentication barriers initial access.

[OBSERVATION] The application appears to be the OWASP Juice Shop.

[OBSERVATION] The application is likely vulnerable for security testing purposes.

[OBSERVATION] Initial access shows no authentication mechanisms.

[OBSERVATION] The application is likely a web application with frontend components.

[OBSERVATION] No session or authentication data initial response.

[OBSERVATION] The application is likely OWASP Juice Shop.

[OBSERVATION] Initial response shows a modern web application structure.

[OBSERVATION] The application appears to be a vulnerable web application for training.

[OBSERVATION] The response contains Material Design CSS variables.

[OBSERVATION] No authentication required initial access.

[OBSERVATION] The application is likely the OWASP Juice Shop vulnerable application.

[OBSERVATION] Initial response shows Angular and Material components.

[OBSERVATION] The application is using standard web application frameworks.

[OBSERVATION] No authentication tokens or session data initial response.

[OBSERVATION] The application appears to be a frontend web application with Angular.

[OBSERVATION] The application is likely vulnerable for security training.

[OBSERVATION] Initial access shows no authentication barriers.

[OBSERVATION] The application is likely the OWASP Juice Shop application.

[OBSERVATION] The response contains frontend web application structure.

[OBSERVATION] No authentication mechanisms initial response.

[OBSERVATION] The application is likely a vulnerable web application.

[OBSERVATION] The application appears to be a modern web application with Material Design.

[OBSERVATION] Initial response shows a web application with Angular components.

[OBSERVATION] The application is likely designed for security testing.

[OBSERVATION] No session or authentication data initial response.

[OBSERVATION] The application is likely OWASP Juice Shop with vulnerabilities.

[OBSERVATION] Initial access shows no authentication required.

[OBSERVATION] The application is using Angular frontend with Material Design.

[OBSERVATION] The response indicates a web application with frontend components.

[OBSERVATION] No authentication data initial response.

[OBSERVATION] The application is likely vulnerable for security training.

[OBSERVATION] Initial response shows Angular and Material components.

[OBSERVATION] The application appears to be a frontend web application.

[OBSERVATION] No session identifiers initial response.

[OBSERVATION] The application is likely the OWASP Juice Shop vulnerable application.

[OBSERVATION] The application is likely a vulnerable web application for security testing.

[OBSERVATION] Initial access shows no authentication barriers.

[OBSERVATION] The application is using Material Design components.

[OBSERVATION] The response contains Angular frontend elements.

[OBSERVATION] No authentication required for initial access.

[OBSERVATION] The application is likely a vulnerable web application for training.

[OBSERVATION] Initial response shows a modern web application structure.

[OBSERVATION] The application is likely the OWASP Juice Shop.

[OBSERVATION] No authentication tokens initial response.

[OBSERVATION] The application is using standard web application components.

[OBSERVATION] Initial access shows no session data.

[OBSERVATION] The application is likely vulnerable for security testing.

[OBSERVATION] The response indicates a web application with Angular frontend.

[OBSERVATION] No authentication mechanisms initial response.

[OBSERVATION] The application is likely OWASP Juice Shop.

[OBSERVATION] Initial access shows no authentication barriers.

[OBSERVATION] The application is likely a vulnerable web application for training.

[OBSERVATION] The response contains Material Design CSS variables.

[OBSERVATION] No session identifiers initial response.

[OBSERVATION] The application is likely the OWASP Juice Shop vulnerable application.

[OBSERVATION] Initial response shows a web application with frontend components.

[OBSERVATION] The application is using Angular with Material Design.

[OBSERVATION] No authentication data initial response.

[OBSERVATION] The application is likely vulnerable for security testing.

[OBSERVATION] Initial access shows no authentication required.

[OBSERVATION] The application is likely a frontend web application.

[OBSERVATION] The response contains Angular frontend structure.

[OBSERVATION] No session tokens initial response.

[OBSERVATION] The application is likely the OWASP Juice Shop.

[OBSERVATION] Initial response shows no authentication barriers.

[OBSERVATION] The application is likely a vulnerable web application for security training.

[OBSERVATION] The response indicates a modern web application with Material Design.

[OBSERVATION] No authentication mechanisms initial response.

[OBSERVATION] The application is likely OWASP Juice Shop with vulnerabilities.

[OBSERVATION] Initial access shows no session data.

[OBSERVATION] The application is using Angular frontend components.

[OBSERVATION] No authentication required for initial access.

[OBSERVATION] The application is likely vulnerable for security training.

[OBSERVATION] The response contains Angular and Material components.

[OBSERVATION] Initial response shows a web application with frontend structure.

[OBSERVATION] The application is likely the OWASP Juice Shop vulnerable application.

[OBSERVATION] No authentication tokens or session data initial response.

[OBSERVATION] The application is using Material Design components.

[OBSERVATION] Initial access shows no authentication barriers.

[OBSERVATION] The application is likely a vulnerable web application for security testing.

[OBSERVATION] The response indicates a frontend web application with Angular.

[OBSERVATION] No session identifiers initial response.

[OBSERVATION] The application is likely OWASP Juice Shop.

[OBSERVATION] Initial response shows a modern web application.

[OBSERVATION] The application is likely vulnerable for training purposes.

[OBSERVATION] The response contains Angular frontend elements.

[OBSERVATION] No authentication required for access.

[OBSERVATION] The application is likely the OWASP Juice Shop vulnerable application.

[OBSERVATION] Initial access shows no authentication data.

[OBSERVATION] The application is using Material Design with CSS variables.

[OBSERVATION] No authentication mechanisms initial response.

[OBSERVATION] The application is likely vulnerable for security testing.

[OBSERVATION] Initial response shows Angular and Material components.

[OBSERVATION] The application is likely a frontend web application with Angular.

[OBSERVATION] No session tokens initial response.

[OBSERVATION] The application is likely the OWASP Juice Shop.

[OBSERVATION] Initial access shows no authentication barriers.

[OBSERVATION] The application is likely vulnerable for security training.

[OBSERVATION] The response contains standard web application structure.

[OBSERVATION] No authentication data initial response.

[OBSERVATION] The application is likely OWASP Juice Shop.

[OBSERVATION] Initial response shows no session data.

[OBSERVATION] The application is using Angular with Material Design.

[OBSERVATION] No authentication required for initial access.

[OBSERVATION] The application is likely vulnerable for security testing.

[OBSERVATION] The response contains Angular frontend structure.

[OBSERVATION] Initial access shows no authentication mechanisms.

[OBSERVATION] The application is likely the OWASP Juice Shop vulnerable application.

[OBSERVATION] No session identifiers initial response.

[OBSERVATION] The application is likely a vulnerable web application for training.

[OBSERVATION] The response indicates a web application with Material Design.

[OBSERVATION] No authentication tokens initial response.

[OBSERVATION] The application is likely OWASP Juice Shop.

[OBSERVATION] Initial access shows no authentication barriers.

[OBSERVATION] The application is using frontend web application components.

[OBSERVATION] No authentication required for access.

[OBSERVATION] The application is likely vulnerable for security testing.

[OBSERVATION] The response contains Angular and Material Design components.

[OBSERVATION] Initial response shows a web application structure.

[OBSERVATION] The application is likely the OWASP Juice Shop vulnerable application.

[OBSERVATION] No session data initial response.

[OBSERVATION] The application is likely a frontend web application with Angular.

[OBSERVATION] No authentication mechanisms initial response.

[OBSERVATION] The application is likely vulnerable for security training.

[OBSERVATION] The response contains Material Design CSS variables.

[OBSERVATION] Initial access shows no authentication required.

[OBSERVATION] The application is likely OWASP Juice Shop.

[OBSERVATION] No authentication tokens initial response.

[OBSERVATION] The application is using Angular frontend components.

[OBSERVATION] No session identifiers initial response.

[OBSERVATION] The application is likely vulnerable for security testing.

[OBSERVATION] The response indicates a modern web application with Angular.

[OBSERVATION] Initial access shows no authentication barriers.

[OBSERVATION] The application is likely a vulnerable web application for training.

[OBSERVATION] The response contains frontend web application elements.

[OBSERVATION] No authentication data initial response.

[OBSERVATION] The application is likely OWASP Juice Shop.

[OBSERVATION] Initial response shows no session data.

[OBSERVATION] The application is using Material Design components.

[OBSERVATION] No authentication required for initial access.

[OBSERVATION] The application is likely vulnerable for security testing.

[OBSERVATION] The response contains Angular frontend structure.

[OBSERVATION] Initial access shows no authentication mechanisms.

[OBSERVATION] The application is likely the OWASP Juice Shop vulnerable application.

[OBSERVATION] No session tokens initial response.

[OBSERVATION] The application is likely a frontend web application with Angular.

[OBSERVATION] No authentication barriers initial response.

[OBSERVATION] The application is likely vulnerable for security training.

[OBSERVATION] The response indicates a web application with Material Design.

[OBSERVATION] Initial response shows no authentication required.

[OBSERVATION] The application is likely OWASP Juice Shop.

[OBSERVATION] No authentication tokens initial response.

[OBSERVATION] The application is using standard web application components.

[OBSERVATION] No session identifiers initial response.

[OBSERVATION] The application is likely vulnerable for security testing.

[OBSERVATION] The response contains Angular and Material Design components.

[OBSERVATION] Initial access shows a web application structure.

[OBSERVATION] The application is likely the OWASP Juice Shop vulnerable application.

[OBSERVATION] No authentication data initial response.

[OBSERVATION] The application is likely a frontend web application.

[OBSERVATION] No authentication mechanisms initial response.

[OBSERVATION] The application is likely vulnerable for security training.

[OBSERVATION] The response contains Material Design CSS variables.

[OBSERVATION] Initial access shows no authentication barriers.

[OBSERVATION] The application is likely OWASP Juice Shop.

[OBSERVATION] No session data initial response.

[OBSERVATION] The application is using Angular with Material Design.

[OBSERVATION] No authentication required for access.

[OBSERVATION] The application is likely vulnerable for security testing.

[OBSERVATION] The response indicates a web application with frontend components.

[OBSERVATION] Initial access shows no authentication mechanisms.

[OBSERVATION] The application is likely the OWASP Juice Shop vulnerable application.

[OBSERVATION] No session tokens initial response.

[OBSERVATION] The application is likely a frontend web application with Angular.

[OBSERVATION] No authentication barriers initial response.

[OBSERVATION] The application is likely vulnerable for security training.

[OBSERVATION] The response contains standard web application elements.

[OBSERVATION] Initial response shows no authentication required.

[OBSERVATION] The application is likely OWASP Juice Shop.

[OBSERVATION] No authentication tokens initial response.

[OBSERVATION] The application is using Material Design components.

[OBSERVATION] No session identifiers initial response.

[OBSERVATION] The application is likely vulnerable for security testing.

[OBSERVATION] The response contains Angular frontend structure.

[OBSERVATION] Initial access shows a web application structure.

[OBSERVATION] The application is likely the OWASP Juice Shop vulnerable application.

[OBSERVATION] No authentication data initial response.

[OBSERVATION] The application is likely a frontend web application.

[OBSERVATION] No authentication mechanisms initial response.

[OBSERVATION] The application is likely vulnerable for security training.

[OBSERVATION] The response indicates Material Design components.

[OBSERVATION] Initial access shows no authentication barriers.

[OBSERVATION] The application is likely OWASP Juice Shop.

[OBSERVATION] No session data initial response.

[OBSERVATION] The application is using Angular frontend components.

[OBSERVATION] No authentication required for access.

[OBSERVATION] The application is likely vulnerable for security testing.

[OBSERVATION] The response contains Angular and Material Design elements.

[OBSERVATION] Initial response shows a web application structure.

[OBSERVATION] The application is likely the OWASP Juice Shop vulnerable application.

[OBSERVATION] No authentication tokens initial response.

[OBSERVATION] The application is likely a frontend web application with Angular.

[OBSERVATION] No authentication barriers initial response.

[OBSERVATION] The application is likely vulnerable for security training.

[OBSERVATION] The response contains standard web application structure.

[OBSERVATION] Initial access shows no authentication mechanisms.

[OBSERVATION] The application is likely OWASP Juice Shop.

[OBSERVATION] No session identifiers initial response.

[OBSERVATION] The application is using Material Design components.

[OBSERVATION] No authentication required for initial access.

[OBSERVATION] The application is likely vulnerable for security testing.

[OBSERVATION] The response indicates a modern web application.

[OBSERVATION] Initial access shows no authentication barriers.

[OBSERVATION] The application is likely a vulnerable web application for training.

[OBSERVATION] The response contains Angular frontend elements.

[OBSERVATION] No authentication data initial response.

[OBSERVATION] The application is likely OWASP Juice Shop.

[OBSERVATION] No session tokens initial response.

[OBSERVATION] The application is using Angular with Material Design.

[OBSERVATION] Initial access shows no authentication required.

[OBSERVATION] The application is likely vulnerable for security testing.

[OBSERVATION] The response contains Material Design CSS variables.

[OBSERVATION] No authentication mechanisms initial response.

[OBSERVATION] The application is likely the OWASP Juice Shop vulnerable application.

[OBSERVATION] No session data initial response.

[OBSERVATION] The application is likely a frontend web application.

[OBSERVATION] Initial access shows no authentication barriers.

[OBSERVATION] The application is likely vulnerable for security training.

[OBSERVATION] The response contains Angular and Material Design components.

[OBSERVATION] No authentication tokens initial response.

[OBSERVATION] The application is likely OWASP Juice Shop.

[OBSERVATION] No session identifiers initial response.

[OBSERVATION] The application is using standard web application components.

[OBSERVATION] Initial response shows a web application structure.

[OBSERVATION] The application is likely vulnerable for security testing.

[OBSERVATION] The response indicates Angular frontend with Material Design.

[OBSERVATION] No authentication required for access.

[OBSERVATION] The application is likely the OWASP Juice Shop vulnerable application.

[OBSERVATION] No authentication data initial response.

[OBSERVATION] The application is likely a frontend web application with Angular.

[OBSERVATION] Initial access shows no authentication mechanisms.

[OBSERVATION] The application is likely vulnerable for security training.

[OBSERVATION] The response contains Material Design CSS variables.

[OBSERVATION] No session tokens initial response.

[OBSERVATION] The application is likely OWASP Juice Shop.

[OBSERVATION] No authentication barriers initial response.

[OBSERVATION] The application is using Angular frontend components.

[OBSERVATION] Initial access shows no session data.

[OBSERVATION] The application is likely vulnerable for security testing.

[OBSERVATION] The response contains standard web application elements.

[OBSERVATION] No authentication required for initial access.

[OBSERVATION] The application is likely the OWASP Juice Shop vulnerable application.

[OBSERVATION] The application is likely a frontend web application.

[OBSERVATION] No authentication mechanisms initial response.

[OBSERVATION] The application is likely vulnerable for security training.

[OBSERVATION] The response indicates Material Design components.

[OBSERVATION] No session identifiers initial response.

[OBSERVATION] The application is likely OWASP Juice Shop.

[OBSERVATION] Initial access shows no authentication barriers.

[OBSERVATION] The application is using Angular with Material Design.

[OBSERVATION] No authentication tokens initial response.

[OBSERVATION] The application is likely vulnerable for security testing.

[OBSERVATION] The response contains Angular frontend structure.

[OBSERVATION] Initial response shows a web application structure.

[OBSERVATION] The application is likely the OWASP Juice Shop vulnerable application.

[OBSERVATION] No authentication data initial response.

[OBSERVATION] The application is likely a frontend web application with Angular.

[OBSERVATION] No authentication required for access.

[OBSERVATION] The application is likely vulnerable for security training.

[OBSERVATION] The response contains Material Design CSS variables.

[OBSERVATION] Initial access shows no authentication mechanisms.

[OBSERVATION] The application is likely OWASP Juice Shop.

[OBSERVATION] No session tokens initial response.

[OBSERVATION] The application is using standard web application components.

[OBSERVATION] No authentication barriers initial response.

[OBSERVATION] The application is likely vulnerable for security testing.

[OBSERVATION] The response indicates Angular frontend with Material Design.

[OBSERVATION] Initial access shows no session data.

[OBSERVATION] The application is likely the OWASP Juice Shop vulnerable application.

[OBSERVATION] No authentication tokens initial response.

[OBSERVATION] The application is likely a frontend web application.

[OBSERVATION] No authentication required for initial access.

[OBSERVATION] The application is likely vulnerable for security training.

[OBSERVATION] The response contains Angular and Material Design elements.

[OBSERVATION] Initial response shows a web application structure.

[OBSERVATION] The application is likely OWASP Juice Shop.

[OBSERVATION] No authentication data initial response.

[OBSERVATION] The application is using Angular frontend components.

[OBSERVATION] No session identifiers initial response.

[OBSERVATION] The application is likely vulnerable for security testing.

[OBSERVATION] The response indicates Material Design components.

[OBSERVATION] Initial access shows no authentication barriers.

[OBSERVATION] The application is likely the OWASP Juice Shop vulnerable application.

[OBSERVATION] No authentication mechanisms initial response.

[OBSERVATION] The application is likely a frontend web application with Angular.

[OBSERVATION] No authentication required for access.

[OBSERVATION] The application is likely vulnerable for security training.

[OBSERVATION] The response contains standard web application structure.

[OBSERVATION] Initial response shows no session data.

[OBSERVATION] The application is likely OWASP Juice Shop.

[OBSERVATION] No authentication tokens initial response.

[OBSERVATION] The application is using Material Design components.

[OBSERVATION] No authentication barriers initial response.

[OBSERVATION] The application is likely vulnerable for security testing.

[OBSERVATION] The response indicates Angular frontend with Material Design.

[OBSERVATION] Initial access shows no authentication mechanisms.

[OBSERVATION] The application is likely the OWASP Juice Shop vulnerable application.

[OBSERVATION] No session tokens initial response.

[OBSERVATION] The application is likely a frontend web application.

[OBSERVATION] No authentication required for initial access.

[OBSERVATION] The application is likely vulnerable for security training.

[OBSERVATION] The response contains Angular and Material Design components.

[OBSERVATION] Initial response shows a web application structure.

[OBSERVATION] The application is likely OWASP Juice Shop.

[OBSERVATION] No authentication data initial response.

[OBSERVATION] The application is using Angular with Material Design.

[OBSERVATION] No session identifiers initial response.

[OBSERVATION] The application is likely vulnerable for security testing.

[OBSERVATION] The response indicates Material Design CSS variables.

[OBSERVATION] Initial access shows no authentication barriers.

[OBSERVATION] The application is likely the OWASP Juice Shop vulnerable application.

[OBSERVATION] No authentication mechanisms initial response.

[OBSERVATION] The application is likely a frontend web application with Angular.

[OBSERVATION] No authentication required for access.

[OBSERVATION] The application is likely vulnerable for security training.

[OBSERVATION] The response contains standard web application elements.

[OBSERVATION] Initial response shows no session data.

[OBSERVATION] The application is likely OWASP Juice Shop.

[OBSERVATION] No authentication tokens initial response.

[OBSERVATION] The application is using standard web application components.

[OBSERVATION] No authentication barriers initial response.

[OBSERVATION] The application is likely vulnerable for security testing.

[OBSERVATION] The response indicates Angular frontend with Material Design.

[OBSERVATION] Initial access shows no authentication mechanisms.

[OBSERVATION] The application is likely the OWASP Juice Shop vulnerable application.

[OBSERVATION] No session tokens initial response.

[OBSERVATION] The application is likely a frontend web application.

[OBSERVATION] No authentication required for initial access.

[OBSERVATION] The application is likely vulnerable for security training.

[OBSERVATION] The response contains Angular and Material Design elements.

[OBSERVATION] Initial response shows a web application structure.

[OBSERVATION] The application is likely OWASP Juice Shop.

[OBSERVATION] No authentication data initial response.

[OBSERVATION] The application is using Angular frontend components.

[OBSERVATION] No session identifiers initial response.

[OBSERVATION] The application is likely vulnerable for security testing.

[OBSERVATION] The response indicates Material Design components.

[OBSERVATION] Initial access shows no authentication barriers.

[OBSERVATION] The application is likely the OWASP Juice Shop vulnerable application.

[OBSERVATION] No authentication mechanisms initial response.

[OBSERVATION] The application is likely a frontend web application with Angular.

[OBSERVATION] No authentication required for access.

[OBSERVATION] The application is likely vulnerable for security training.

[OBSERVATION] The response contains standard web application structure.

[OBSERVATION] Initial response shows no session data.

[OBSERVATION] The application is likely OWASP Juice Shop.

[OBSERVATION] No authentication tokens initial response.

[OBSERVATION] The application is using Material Design components.

[OBSERVATION] No authentication barriers initial response.

[OBSERVATION] The application is likely vulnerable for security testing.

[OBSERVATION] The response indicates Angular frontend with Material Design.

[OBSERVATION] Initial access shows no authentication mechanisms.

[OBSERVATION] The application is likely the OWASP Juice Shop vulnerable application.

[OBSERVATION] No session tokens initial response.

[OBSERVATION] The application is likely a frontend web application.

[OBSERVATION] No authentication required for initial access.

[OBSERVATION] The application is likely vulnerable for security training.

[OBSERVATION] The response contains Angular and Material Design components.

[OBSERVATION] Initial response shows a web application structure.

[OBSERVATION] The application is likely OWASP Juice Shop.

[OBSERVATION] No authentication data initial response.

[OBSERVATION] The application is using Angular with Material Design.

[OBSERVATION] No session identifiers initial response.

[OBSERVATION] The application is likely vulnerable for security testing.

[OBSERVATION] The response indicates Material Design CSS variables.

[OBSERVATION] Initial access shows no authentication barriers.

[OBSERVATION] The application is likely the OWASP Juice Shop vulnerable application.

[OBSERVATION] No authentication mechanisms initial response.

[OBSERVATION] The application is likely a frontend web application with Angular.

[OBSERVATION] No authentication required for access.

[OBSERVATION] The application is likely vulnerable for security training.

[OBSERVATION] The response contains standard web application elements.

[OBSERVATION] Initial response shows no session data.

[OBSERVATION] The application is likely OWASP Juice Shop.

[OBSERVATION] No authentication tokens initial response.

[OBSERVATION] The application is using standard web application components.

[OBSERVATION] No authentication barriers initial response.

[OBSERVATION] The application is likely vulnerable for security testing.

[OBSERVATION] The response indicates Angular frontend with Material Design.

[OBSERVATION] Initial access shows no authentication mechanisms.

[OBSERVATION] The application is likely the OWASP Juice Shop vulnerable application.

[OBSERVATION] No session tokens initial response.

[OBSERVATION] The application is likely a frontend web application.

[OBSERVATION] No authentication required for initial access.

[OBSERVATION] The application is likely vulnerable for security training.

[OBSERVATION] The response contains Angular and Material Design elements.

[OBSERVATION] Initial response shows a web application structure.

[OBSERVATION] The application is likely OWASP Juice Shop.

[OBSERVATION] No authentication data initial response.

[OBSERVATION] The application is using Angular frontend components.

[OBSERVATION] No session identifiers initial response.

[OBSERVATION] The application is likely vulnerable for security testing.

[OBSERVATION] The response indicates Material Design components.

[OBSERVATION] Initial access shows no authentication barriers.

[OBSERVATION] The application is likely the OWASP Juice Shop vulnerable application.

[OBSERVATION] No authentication mechanisms initial response.

[OBSERVATION] The application is likely a frontend web application with Angular.

[OBSERVATION] No authentication required for access.

[OBSERVATION] The application is likely vulnerable for security training.

[OBSERVATION] The response contains standard web application structure.

[OBSERVATION] Initial response shows no session data.

[OBSERVATION] The application is likely OWASP Juice Shop.

[OBSERVATION] No authentication tokens initial response.

[OBSERVATION] The application is using Material Design components.

[OBSERVATION] No authentication barriers initial response.

[OBSERVATION] The application is likely vulnerable for security testing.

[OBSERVATION] The response indicates Angular frontend with Material Design.

[OBSERVATION] Initial access shows no authentication mechanisms.

[OBSERVATION] The application is likely the OWASP Juice Shop vulnerable application.

[OBSERVATION] No session tokens initial response.

[OBSERVATION] The application is likely a frontend web application.

[OBSERVATION] No authentication required for initial access.

[OBSERVATION] The application is likely vulnerable for security training.

[OBSERVATION] The response contains Angular and Material Design components.

[OBSERVATION] Initial response shows a web application structure.

[OBSERVATION] The application is likely OWASP Juice Shop"""


def test_juice_shop_excessive_observations_newlines():
    result = reduce_lines_lossy(JUICE_SHOP_EXCESSIVE_OBSERVATIONS, max_lines=30)
    assert len(result.to_text().splitlines()) == 30
    result = reduce_lines_lossy(JUICE_SHOP_EXCESSIVE_OBSERVATIONS, similarity_threshold=0.5)
    assert len(result.to_text().splitlines()) == 10


def test_juice_shop_excessive_observations_one_line():
    result = reduce_lines_lossy(JUICE_SHOP_EXCESSIVE_OBSERVATIONS.replace('\n', ' '), similarity_threshold=0.5)
    assert len(result.to_text().splitlines()) == 11


def test_juice_shop_excessive_observations_semicolon():
    result = reduce_lines_lossy(JUICE_SHOP_EXCESSIVE_OBSERVATIONS.replace('\n', '; '), similarity_threshold=0.5)
    assert len(result.to_text().splitlines()) == 11


def test_juice_shop_excessive_observations_colon():
    result = reduce_lines_lossy(JUICE_SHOP_EXCESSIVE_OBSERVATIONS.replace('\n', ': '), similarity_threshold=0.5)
    assert len(result.to_text().splitlines()) == 11
