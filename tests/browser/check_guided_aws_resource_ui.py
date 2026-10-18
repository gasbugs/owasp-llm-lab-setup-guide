"""Compare the three AWS resource toolbars and console shortcuts without AWS mutations."""
from playwright.sync_api import sync_playwright, expect


def resource(kind, name):
    return {"type": kind, "name": name, "state": "present",
            "console_url": f"https://us-east-1.console.aws.amazon.com/bedrock/home?resource={name}"}


with sync_playwright() as playwright:
    browser = playwright.chromium.launch()
    page = browser.new_page(viewport={"width": 1440, "height": 1000})
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.goto("http://127.0.0.1:28097/", wait_until="networkidle")
    fixtures = {
        "P02": {"state": "present", "resources": [resource("S3 source bucket", "source")]},
        "P03": {"state": "present", "search_ready": True, "resources": [
            resource(kind, f"resource-{index}") for index, kind in enumerate((
                "S3 source bucket", "S3 vector bucket", "Vector index",
                "IAM role", "Knowledge Base", "Data source"))]},
        "P04": {"state": "present", "model_ready": True,
                "resources": [resource("AWS Guardrail", "guardrail")]},
    }
    for problem, count, category in (("P02", 2, 1), ("P03", 6, 1), ("P04", 1, 2)):
        page.route(f"**/api/resource-status/{problem}", lambda route, request, problem=problem: route.fulfill(
            json={**fixtures[problem], "checked_at": "2026-10-18T00:00:00Z"}))
        page.evaluate("([category, problem]) => { selectTab(category, problem); selectModelCallPane('experience'); }", [category, problem])
        expect(page.locator('#mission-resource-actions [data-problem="%s"]' % problem)).to_be_visible()
        toolbar = page.locator('#mission-resource-actions [data-problem="%s"] .aws-resource-toolbar' % problem)
        expect(toolbar.locator('button')).to_have_count(3)
        expect(page.locator('#aws-console-links [aria-disabled="true"]')).to_have_count(count)
        toolbar.locator('button[data-resource-status]').click()
        expect(page.locator('#aws-console-links a')).to_have_count(count)
        assert all(link.get_attribute('target') == '_blank' for link in page.locator('#aws-console-links a').all())
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
    assert not errors, errors
    browser.close()
print('PASS: P02/P03/P04 share toolbar and console shortcut behavior')
