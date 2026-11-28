#Sources:
#https://playwright.dev/python/docs/intro
#https://playwright.dev/python/docs/test-assertions
#https://betterstack.com/community/guides/testing/playwright-python-intro/
#https://www.youtube.com/watch?v=H2-5ecFwHHQ
#https://playwright.dev/python/docs/auth

#How to start tests effectively: 
# TC01-19: Start the app first with ratelimit_enabled = false in .env, then run pytests tests/ 
# TC-20: turn ratelimit_enabled = true, then run tests again
import os, uuid, pytest
from dotenv import load_dotenv
from playwright.sync_api import Page, expect
load_dotenv()

BASE = "http://127.0.0.1:5000" #App URL 
PASSWORD = "Skid-Obedient9-Dealer-Product-Frolic"
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL") #User account created and assigned the admin role in the database
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")

# - - - - - - - - - -
# HELPERS - functions that will be called and tested in the use-cases
# - - - - - - - - - -
#Generates unique random user
def newUser():
    name = "u" + uuid.uuid4().hex[:10]
    return name, name+"@example.com"

def register(page, username, email, password=PASSWORD):
    page.goto(BASE+"/register")
    page.fill("#username", username)
    page.fill("#email", email)
    page.fill("#password", password)
    page.click("main button")

def login(page,email,password=PASSWORD):
    page.goto(BASE+"/login")
    page.fill("#email", email)
    page.fill("#password", password)
    page.click("main button")

def registerAndLogin(page):
    username, email = newUser()
    register(page, username, email)
    login(page,email)
    return username, email

def createPost(page, title, body="Body"):
    page.goto(BASE+"/post/new")
    page.fill("#title", title)
    page.fill("#body", body)
    page.click("main button")

def addComment(page,text):
    page.fill("#comment", text)
    page.click("button:has-text('Comment')")

def logout(page):
    page.click("nav button")


# - - - - - - - - - -
# TESTS (TC01 - TC16)
# - - - - - - - - - -

def test_tc01_register(page: Page):
    username, email = newUser()
    register(page, username, email)
    expect(page.locator(".alert")).to_contain_text("Account Created") #.alert = flash message class

#TC-02 (UC-1 exception: breached password)
def test_tc02_register_breached_password(page: Page):
    username, email = newUser()
    register(page,username,email, "1q2w3e4r5t6y7u8i9o0p")
    expect(page.locator(".alert")).to_contain_text("commonly breached")

#TC-03 (UC-2 normal flow)
def test_tc_03_login(page: Page):
    registerAndLogin(page)
    expect(page).to_have_url(BASE + "/dashboard")

#TC-04 (UC-2 exception: wrong password)
def test_tc04_login_wrong_password(page: Page):
    username, email = newUser()
    register(page, username, email)
    login(page, email, "wrong-password-123456")
    expect(page.locator(".alert")).to_contain_text("Invalid email or password")

#TC-05 (session is cleared: logout ends the session)
def test_tc05_logout_ends_session(page: Page):
    registerAndLogin(page)
    logout(page)
    page.goto(BASE + "/dashboard")
    expect(page).to_have_url(BASE + "/login")

#TC-06 (UC-3 normal flow: delete account)
def test_tc06_delete_account(page: Page):
    username, email = registerAndLogin(page)
    page.goto(BASE + "/account")
    page.fill("#password", PASSWORD)
    page.click("button:has-text('Delete Account')")
    expect(page.locator(".alert")).to_contain_text("has been deleted")
    login(page, email)
    expect(page.locator(".alert")).to_contain_text("Invalid email or password")

#TC-07 (UC-3 exception: wrong password, nothing deleted)
def test_tc07_delete_account_wrong_password(page: Page):
    registerAndLogin(page)
    page.goto(BASE + "/account")
    page.fill("#password", "wrong-password-123456")
    page.click("button:has-text('Delete Account')")
    expect(page.locator(".alert")).to_contain_text("Password incorrect")

#TC-08 (UC-4: admin sees logs, user gets 403)
def test_tc08_security_logs(page: Page):
    registerAndLogin(page)
    response = page.goto(BASE + "/admin/logs")
    assert response.status == 403
    page.goto(BASE + "/dashboard") #The 403 page has no navbar, so go back before logging out
    logout(page)
    login(page, ADMIN_EMAIL, ADMIN_PASSWORD)
    page.click("text=Security logs")
    expect(page.locator("h1")).to_have_text("Security logs")

#TC-09 (UC-5 normal flow, UC-6 exception: another user cannot edit the post)
def test_tc09_create_post_and_edit_forbidden(page: Page):
    registerAndLogin(page)
    createPost(page, "My first post")
    expect(page.locator("h1")).to_have_text("My first post")
    postUrl = page.url
    logout(page)
    registerAndLogin(page)
    response = page.goto(postUrl + "/edit")
    assert response.status == 403

#TC-10 (UC-7 alternate flow: an admin deletes another user's post)
def test_tc10_admin_deletes_post(page: Page):
    registerAndLogin(page)
    createPost(page, "Someone's post")
    postUrl = page.url
    logout(page)
    login(page, ADMIN_EMAIL, ADMIN_PASSWORD)
    page.goto(postUrl)
    page.click("button:has-text('Delete Post')")
    expect(page.locator(".alert")).to_contain_text("Post deleted")

#TC-11 (UC-8: the search term is shown as text and not run as HTML)
def test_tc11_search_is_escaped(page: Page):
    registerAndLogin(page)
    createPost(page, "Find <i>term</i> " + uuid.uuid4().hex[:6])
    page.goto(BASE + "/dashboard?q=<i>term</i>")
    expect(page.locator("main i")).to_have_count(0)
    expect(page.locator("main")).to_contain_text("<i>term</i>")

#TC-12 (UC-9: a comment is shown as text and not run as HTML)
def test_tc12_comment_is_escaped(page: Page):
    registerAndLogin(page)
    createPost(page, "Comment test")
    addComment(page, "<b>not bold</b>")
    expect(page.locator(".comment-body")).to_have_text("<b>not bold</b>")
    expect(page.locator(".comment-body b")).to_have_count(0)

#TC-13 (UC-10 normal flow: user edits own comment)
def test_tc13_edit_own_comment(page: Page):
    registerAndLogin(page)
    createPost(page, "Post")
    addComment(page, "First version")
    page.click("text=Edit comment")
    page.fill("#body", "Second version")
    page.click("main button")
    expect(page.locator(".comment-body")).to_have_text("Second version")

#TC-14 (UC-11 exception: another user cannot delete the comment)
def test_tc14_delete_other_users_comment(page: Page):
    registerAndLogin(page)
    createPost(page, "Post")
    addComment(page, "Not yours to delete")
    deleteUrl = page.locator(".comment form").get_attribute("action")
    postUrl = page.url
    logout(page)
    registerAndLogin(page)
    page.goto(postUrl)
    expect(page.locator(".comment button")).to_have_count(0)
    token = page.locator("input[name=csrf_token]").first.get_attribute("value")
    response = page.request.post(BASE + deleteUrl, form={"csrf_token": token})
    assert response.status == 403

#TC-15 (security headers)
def test_tc15_security_headers(page: Page):
    response = page.goto(BASE + "/")
    assert "default-src 'self'" in response.headers["content-security-policy"]
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["x-content-type-options"] == "nosniff"

#TC-16 (UC-8 normal flow N7: search.js highlights the word as text so DOM-based XSS cannot run)
def test_tc16_highlight_is_text(page: Page):
    registerAndLogin(page)
    createPost(page, "Find <i>me</i> " + uuid.uuid4().hex[:6])
    page.goto(BASE + "/dashboard?q=<i>me</i>")
    expect(page.locator(".post-row mark").first).to_have_text("<i>me</i>")
    expect(page.locator("main i")).to_have_count(0)

#TC-17 (UC-8 normal flow N5: a quote in the search is treated as data and not SQL)
def test_tc17_search_with_quote(page: Page):
    registerAndLogin(page)
    title = "O'Brien's post " + uuid.uuid4().hex[:6]
    createPost(page, title)
    response = page.goto(BASE + "/dashboard?q=O'Brien")
    assert response.status == 200
    expect(page.locator(".post-row", has_text=title)).to_have_count(1)

#TC-18 (UC-5 exception E2: a form sent without a CSRF token is refused and nothing is saved)
def test_tc18_post_without_csrf_token(page: Page):
    registerAndLogin(page)
    title = "No token " + uuid.uuid4().hex[:6]
    response = page.request.post(BASE + "/post/new", form={"title": title, "body": "Body"}) #No csrf_token, like a form on another website
    assert response.url == BASE + "/dashboard"
    assert "Session expired, please try again" in response.text()
    page.goto(BASE + "/dashboard?q=" + title)
    expect(page.locator("text=No posts found.")).to_have_count(1)

#TC-19 (UC-4: failed logins, rejected input and CSRF failures are logged as warnings, and emails are never logged)
def test_tc19_security_events_logged(page: Page):
    username, email = newUser()
    register(page, username, email)
    login(page, email, "wrong-password-123456") #failed_login
    login(page, email)
    createPost(page, "Log test")
    token = page.locator("input[name=csrf_token]").first.get_attribute("value")
    page.request.post(page.url + "/comment", form={"csrf_token": token, "body": "x" * 1001}) #Skips the browser's maxlength, so only the server check stops it: rejected_input
    page.request.post(BASE + "/post/new", form={"title": "t", "body": "b"}) #No token: csrf_failed
    page.goto(BASE + "/dashboard")
    logout(page)
    login(page, ADMIN_EMAIL, ADMIN_PASSWORD)
    page.goto(BASE + "/admin/logs")
    for action in ["failed_login", "rejected_input", "csrf_failed"]:
        expect(page.locator("tr.warning", has_text=username).filter(has_text=action)).to_have_count(1)
    expect(page.locator("table.summary")).to_contain_text("failed_login")
    expect(page.locator("main")).not_to_contain_text(email)

#TC-20 (UC-2 exception E4: the sixth login in a minute is blocked)
#Only runs when RATELIMIT_ENABLED=true in .env. Restart the app with that setting, then run: pytest tests/ -k tc20 -v
@pytest.mark.skipif(
    os.getenv("RATELIMIT_ENABLED", "true").strip().lower() == "false",
    reason="rate limit is disabled via RATELIMIT_ENABLED=false",
)
def test_tc20_login_rate_limit(page: Page):
    for attempt in range(6):
        login(page, "nobody@example.com", "wrong-password-123456")
    expect(page.locator("body")).to_contain_text("429 Too Many Requests")

#TC-24 (UC-2 login: SQL injection in the email field is treated as data and not SQL)
def test_tc24_login_sql_injection(page: Page):
    registerAndLogin(page)   #makes sure at least one user exists in the users table
    logout(page)

    page.goto(BASE + "/login")
    #browser validation only checks the email format; turn it off so the payload reaches the server
    page.evaluate("document.querySelector('form').noValidate = true")
    page.fill("#email", "' OR '1'='1'#")
    page.fill("#password", "anything")
    page.click("main button")

    #secure: the query is parameterised, so the injected string matches no user and login fails
    expect(page).to_have_url(BASE + "/login")
    expect(page.locator("body")).to_contain_text("Invalid email or password.")