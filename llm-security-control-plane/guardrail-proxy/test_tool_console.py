"""Offline browser contract for the Bedrock tool fixture console path."""

from pathlib import Path
from playwright.sync_api import sync_playwright, expect

ui = Path(__file__).resolve().parent / "ui"

with sync_playwright() as playwright:
    browser = playwright.chromium.launch()
    page = browser.new_page()
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    def serve_ui(route):
        name = route.request.url.split("/console/", 1)[1].split("#", 1)[0]
        file = ui / (name or "index.html")
        assert file.resolve().parent == ui.resolve() and file.is_file(), name
        route.fulfill(path=str(file))

    page.route("http://tool-fixture.test/console/**", serve_ui)
    page.goto("http://tool-fixture.test/console/#testing", wait_until="networkidle")
    page.evaluate("""() => {
      showPolicy({name:"Fixture",version:"0.1.3",digest:"a".repeat(64),
        model_id:"us.amazon.nova-lite-v1:0",
        stages:["presidio_input","nemo_input","main","nemo_output","presidio_output"],
        retrieval_fixture_available:true,tool_fixture_available:true,native_tool_rail:false});
      callerToken="test-caller";
      window.toolRequest=null;
      window.fetch=async (url, options={}) => {
        if(url==="/v1/tool-chat"){
          window.toolRequest={url,body:JSON.parse(options.body)};
          return {ok:true,status:200,json:async()=>({
            request_id:"request-1",policy_digest:"a".repeat(64),decision:"block",
            stopped_at:"tool_input",upstream_called:false,main_completed:false,
            tool_executed:false,stages:[
              {name:"presidio_input",result:"passed"},
              {name:"nemo_input",result:"passed"},
              {name:"tool_input",result:"blocked"}]})};
        }
        if(url==="/v1/requests")return {ok:true,status:200,
          json:async()=>({requests:[{request_id:"request-1",
            policy_digest:"a".repeat(64),decision:"block",stopped_at:"tool_input",
            upstream_called:false,main_completed:false,stages:[
              {name:"presidio_input",result:"passed"},
              {name:"nemo_input",result:"passed"},
              {name:"tool_input",result:"blocked"}]}]})};
        throw new Error("unexpected path "+url);
      };
      document.getElementById("run-test").disabled=false;
    }""")
    page.select_option("#test-path", "status-unknown-tool")
    page.click("#run-test")
    expect(page.locator("#test-heading")).to_have_text("차단 · HTTP 200")
    expect(page.locator("#test-summary")).to_contain_text("도구 미실행")
    assert page.evaluate("window.toolRequest") == {
        "url": "/v1/tool-chat",
        "body": {"message": "What is one safe account recovery tip?",
                 "fixture_id": "status-unknown-tool"}}
    expect(page.locator("#test-stages")).to_contain_text("도구 호출: blocked")
    assert page.locator("#test-path option[value='status-safe']").is_enabled()
    page.evaluate("""() => showPolicy({name:"Old",version:"0.1.1",digest:"b".repeat(64),
      model_id:"us.amazon.nova-lite-v1:0",
      stages:["presidio_input","nemo_input","main","nemo_output","presidio_output"],
      retrieval_fixture_available:false,tool_fixture_available:false})""")
    assert page.locator("#test-path option[value='status-safe']").is_disabled()
    assert page.locator("#test-path option[value='recovery-safe']").is_disabled()
    assert not errors, errors
    browser.close()
print("tool_console=PASS cases=tool_route,stage_label,old_policy_disabled")
