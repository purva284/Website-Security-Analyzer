
import requests
from datetime import datetime
from urllib.parse import urlparse

SECURITY_HEADERS = {
    "Content-Security-Policy":
      "Helps reduce certain cross-site scripting and content injection risks.",
    "Strict-Transport-Security":
        "Helps browsers use HTTPS for future connections.",
    "X-Content-Type-Options":
        "Helps prevent browsers from guessing file content types.",
    "X-Frame-Options":
        "Helps protect against clickjacking.",
    "Referrer-Policy":
        "Controls how much referrer information browsers share.",
    "Permissions-Policy":
        "Controls access to selected browser features."
}


def analyze_website(website):
    results = []

    parsed_url = urlparse(website)

    # Validate the URL
    if (
        parsed_url.scheme not in ("http", "https")
        or not parsed_url.hostname
        or parsed_url.username
        or parsed_url.password
    ):
        print(
            "Invalid URL. Enter a valid URL starting "
            "with http:// or https://"
        )
        return None

    results.append("WEBSITE SECURITY ANALYSIS REPORT")
    results.append("=" * 50)
    results.append(f"Website: {website}")
    results.append(
        f"Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )

    try:
        # Connect to the website.
        # TLS certificate verification is enabled by default.
        response = requests.get(
            website,
            timeout=10,
            allow_redirects=True,
            headers={
                "User-Agent": "WebsiteSecurityAnalyzer/1.0"
            }
        )

        results.append("")
        results.append("CONNECTION AND HTTPS CHECK")
        results.append("-" * 50)
        results.append(f"HTTP status code: {response.status_code}")
        results.append(f"Final URL: {response.url}")
        results.append(
            f"Redirects followed: {len(response.history)}"
        )

        final_url = urlparse(response.url)

        if final_url.scheme == "https":
            results.append(
                "HTTPS: The final connection uses HTTPS."
            )
            results.append(
                "TLS certificate: The certificate was accepted "
                "by the default verification checks."
            )
        else:
            results.append(
                "WARNING: The final connection uses HTTP, not HTTPS."
            )
            results.append(
                "The connection is not protected by HTTPS."
            )

        if parsed_url.scheme == "http" and final_url.scheme == "https":
            results.append(
                "Note: The original HTTP URL redirected to HTTPS."
            )
        elif parsed_url.scheme == "http":
            results.append(
                "WARNING: The original URL does not use HTTPS."
            )

        for number, redirect in enumerate(
            response.history, start=1
        ):
            results.append(
                f"Redirect {number}: "
                f"{redirect.status_code} -> {redirect.url}"
            )

        # Check security headers
        results.append("")
        results.append("SECURITY HEADER CHECK")
        results.append("-" * 50)

        missing_headers = []

        for header, explanation in SECURITY_HEADERS.items():
            if header in response.headers:
                results.append(f"[PRESENT] {header}")
            else:
                results.append(f"[MISSING] {header}")
                results.append(f"  Why it matters: {explanation}")
                missing_headers.append(header)

        results.append("")
        results.append("HEADER SUMMARY")
        results.append("-" * 50)
        results.append(
            f"Headers present: "
            f"{len(SECURITY_HEADERS) - len(missing_headers)}"
            f"/{len(SECURITY_HEADERS)}"
        )
        results.append(
            f"Headers missing: {len(missing_headers)}"
        )

        # Check cookies received in the response
        results.append("")
        results.append("COOKIE SECURITY CHECK")
        results.append("-" * 50)

        cookies = response.cookies

        if not cookies:
            results.append(
                "No cookies were received in the final response."
            )
        else:
            for cookie in cookies:
                results.append(f"Cookie name: {cookie.name}")
                results.append(
                    f"  Secure flag: "
                    f"{'Yes' if cookie.secure else 'No'}"
                )

                cookie_attributes = {
                    str(key).lower(): value
                    for key, value in cookie._rest.items()
                }

                http_only = "httponly" in cookie_attributes
                results.append(
                    f"  HttpOnly flag: "
                    f"{'Yes' if http_only else 'Not detected'}"
                )

                same_site = cookie_attributes.get(
                    "samesite", "Not detected"
                )
                results.append(f"  SameSite attribute: {same_site}")

                if not cookie.secure:
                    results.append(
                        "  WARNING: Secure flag was not detected."
                    )

                if not http_only:
                    results.append(
                        "  Note: HttpOnly flag was not detected."
                    )

        # Explain the report's limitations
        results.append("")
        results.append("IMPORTANT NOTES")
        results.append("-" * 50)
        results.append(
            "Missing security headers do not automatically mean "
            "a website is vulnerable."
        )
        results.append(
            "A successful HTTPS connection means the certificate "
            "passed the checks performed by the requests library; "
            "it does not guarantee the entire website is safe."
        )
        results.append(
            "Cookie checks cover cookies received in the final "
            "response, not every cookie the website may use."
        )
        results.append(
            "This tool performs basic checks only. It is not a "
            "full vulnerability scan or penetration test."
        )

    except requests.exceptions.SSLError:
        results.append("")
        results.append("CONNECTION ERROR")
        results.append(
            "TLS/SSL certificate verification failed. "
            "The connection could not be verified."
        )

    except requests.exceptions.Timeout:
        results.append("")
        results.append("CONNECTION ERROR")
        results.append(
            "The request timed out. Try again later."
        )

    except requests.exceptions.ConnectionError:
        results.append("")
        results.append("CONNECTION ERROR")
        results.append(
            "Could not connect. Check the URL and internet connection."
        )

    except requests.exceptions.RequestException as error:
        results.append("")
        results.append("REQUEST ERROR")
        results.append(str(error))

    return results


def main():
    print("=" * 50)
    print("       WEBSITE SECURITY ANALYZER")
    print("=" * 50)

    website = input(
        "Enter website URL (e.g. https://example.com): "
    ).strip()

    if not website:
        print("Error: Website URL cannot be empty.")
        return

    results = analyze_website(website)

    if results is None:
        return

    print()

    for line in results:
        print(line)

    report_name = "website_security_report.txt"

    try:
        with open(
            report_name, "w", encoding="utf-8"
        ) as report:
            report.write("\n".join(results) + "\n")

        print(f"\nReport saved to: {report_name}")

    except OSError as error:
        print(f"\nCould not save report: {error}")


if __name__ == "__main__":
    main()
