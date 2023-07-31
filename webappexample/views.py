import json
from authlib.integrations.django_client import OAuth
from django.conf import settings
from django.shortcuts import redirect, render, redirect
from django.urls import reverse, resolve
from django.http import JsonResponse
from urllib.parse import quote_plus, urlencode
import requests
import jwt

oauth = OAuth()

oauth.register(
    "auth0",
    client_id=settings.AUTH0_CLIENT_ID,
    client_secret=settings.AUTH0_CLIENT_SECRET,
    audience='https://'+settings.AUTH0_AUDIENCE,
    api_base_url=settings.AUTH0_DOMAIN,
    access_token_url='https://'+settings.AUTH0_DOMAIN +'/oauth/token',
    redirect_uri=settings.AUTH0_DOMAIN + '/callback',
    authorize_params={"audience":settings.AUTH0_AUDIENCE},
    authorize_url='https://' + settings.AUTH0_DOMAIN + '/authorize',
    client_kwargs={
        "scope": "openid email profile read:results",
    },
    server_metadata_url=f"https://{settings.AUTH0_DOMAIN}/.well-known/openid-configuration",
)

def get_auth_token():
    url = "https://dev-1fvz6325acw860zv.us.auth0.com/oauth/token"
    audience = "https://dev-1fvz6325acw860zv.us.auth0.com/api/v2/" 
    payload = {
        "client_id": settings.AUTH0_CLIENT_ID,
        "client_secret": settings.AUTH0_CLIENT_SECRET,
        "audience": audience,
        "grant_type": "client_credentials",
    }
    headers = { 'content-type': "application/json"}
    response = requests.post(url, json=payload, headers=headers)
    if response.status_code == 200:
        data = response.json()
        access_token = data["access_token"]
        return access_token
    else:
        # Handle the error if the API call was not successful
        response.raise_for_status()
        return None

def index(request):
    return render(
        request,
        "index.html",
        context={
            "session": request.session.get("user"),
            "pretty": json.dumps(request.session.get("user"), indent=4),
        },
    )


def callback(request):
    token = oauth.auth0.authorize_access_token(request)
    request.session["user"] = token
    return redirect(request.build_absolute_uri(reverse("index")))


def login(request):
    return oauth.auth0.authorize_redirect(
        request, request.build_absolute_uri(reverse("callback"))
    )


def logout(request):
    request.session.clear()

    return redirect(
        f"https://{settings.AUTH0_DOMAIN}/v2/logout?"
        + urlencode(
            {
                "returnTo": request.build_absolute_uri(reverse("index")),
                "client_id": settings.AUTH0_CLIENT_ID,
            },
            quote_via=quote_plus,
        ),
    )


def actions(request):
    #checks if it has read:triggers as a permission in the scope
    has_read_triggers_permission = False
    permissions = request.session.get("user")['scope'].split()
    if 'read:triggers' in permissions:
        has_read_triggers_permission = True
    
    headers = { 'content-type': "application/json"}
    
    api_url_clients = f"https://{settings.AUTH0_DOMAIN}/api/v2/clients?fields=name"
    api_url_actions = f"https://{settings.AUTH0_DOMAIN}/api/v2/actions/actions"

    headers = {
        'Accept': 'application/json',
        'Authorization': 'Bearer ' + get_auth_token(),  
    }

    clients = requests.get(api_url_clients, headers=headers)
    clients.raise_for_status()

    clientDictionary = {}
    for obj in clients.json():
        name = obj['name']
        if name not in clientDictionary:
            clientDictionary[name] = []
    
    actions = requests.get(api_url_actions, headers=headers)
    actions.raise_for_status()
    for obj in actions.json()['actions']:
        code = obj["code"]
        for key in clientDictionary:
            if key in code:
                if 'Manager' in request.session.get("user")['userinfo']['actions-example.com/roles'] and has_read_triggers_permission:
                    clientDictionary[key].append({'action_id': obj['id'], 'action_name':obj['name'], 'triggers': obj['supported_triggers']})
                else:
                    clientDictionary[key].append({'action_id': obj['id'], 'action_name':obj['name']}) 


    return JsonResponse(clientDictionary, safe=False)

