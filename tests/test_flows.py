#Sources:
#https://playwright.dev/python/docs/intro
#https://playwright.dev/python/docs/test-assertions
#https://betterstack.com/community/guides/testing/playwright-python-intro/
#https://www.youtube.com/watch?v=H2-5ecFwHHQ
#https://playwright.dev/python/docs/auth

#How to start tests effectively: Start the app first with ratelimit_enabled = false in .env, then run pytests tests/ --browser-channel chrome

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
# TESTS
# - - - - - - - - - -

#TC-01 (UC-1 normal flow)
def test_tc01_register(page: Page):
    username, email = newUser()
    register(page, username, email)
    expect(page.locator(".alert")).to_contain_text("Account Created") #.alert = flash message class

