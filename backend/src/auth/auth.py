import json
from flask import request, _request_ctx_stack
from functools import wraps
from jose import jwt
from urllib.request import urlopen


AUTH0_DOMAIN = 'mhcarr-practice.us.auth0.com'
ALGORITHMS = ['RS256']
API_AUDIENCE = 'coffee_shop'

## AuthError Exception
'''
AuthError Exception
A standardized way to communicate auth failure modes
'''
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


## Auth Header

def get_token_auth_header():
    """Obtains token from Authorization Header in request
    """
    auth_header = request.headers.get('Authorization', None)
    
    # if Authorization Header is not in request, raise error
    if not auth: 
        raise AuthError({
            'code': 'Authorization Header is Missing',
            'description': 'Expected Authorization Header'
        }, 401)

    header_parts = auth.split(' ')

    # if header key word is not bearer, raise error
    elif parts[0].lower() != 'bearer':
        raise AuthError({
            'code': 'Invalid Header',
            'description': 'Header must begin with "Bearer"'
        }, 401)

    # if length of header_parts equals 1, token not included, raise error
    elif len(header_parts) == 1:
        raise AuthError({
            'code': 'Invalid Header',
            'description': 'Token was not found'
        }, 401)

    # if length of header_parts is greater than 2, header is not a bearer token, raise error
    elif len(header_parts) > 2:
        raise AuthError({
            'code': 'Invalid Header',
            'description': 'Authorization header must be a Bearer token'
        }, 401)

    token = header_parts[1]
    return token


def check_permissions(permission, payload):
    """Checks permissions in token payload to ensure user has access to endpoint
    """
    # check if payload contains permissions
    if 'permissions' not in payload:
        raise AuthError({
            'code': 'Permissions not found',
            'description': 'Payload did not contain permissions'
        }, 400)

    # check is specific endpoint permission is in payload permissions
    elif permission not in payload['permissions']:
        raise AuthError({
            'code': 'Unauthorized',
            'description': 'No valid permissions for this resource'
        }, 403)
    
    return True


def verify_decode_jwt(token):
    """Verify valid JWT. If valid, return payload

    Function based on code from course lesson
    """
    jsonurl = urlopen('https://{}/.well-known/jwks.json'.format(AUTH0_DOMAIN))
    jwks = json.loads(jsonurl.read())
    unverified_header = jwt.get_unverified_header(token)
    rsa_key = {}
    if 'kid' not in unverified_header:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization malformed'
        }, 401)

    for key in jwks['keys']:
        if key['kid'] == unverified_header['kid']:
            rsa_key = {
                'kty': key['kty'],
                'kid': key['kid'],
                'use': key['use'],
                'n': key['n'],
                'e': key['e']
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=API_AUDIENCE,
                issuer='https://{}/'.format(AUTH0_DOMAIN)
            )

            return payload
    
        except jwt.ExpiredSignatureError:
            raise AuthError({
                'code': 'token_expired',
                'description': 'Token expired'
            }, 401)

        except jwt.JWTClaimsError:
            raise AuthError({
                'code': 'invalid_claims',
                'description': 'Incorrect claims. Please check audience and issuer'
            }, 401)
        
        except Exception:
            raise AuthError({
                'code': 'invalid_header',
                'description': 'Unable to parse authentication token'
            }, 400)
    
    raise AuthError({
        'code': 'invalid_header',
        'description': 'Unable to find the appropriate key'
        }, 400)

def requires_auth(permission=''):
    def requires_auth_decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = get_token_auth_header()
            payload = verify_decode_jwt(token)
            check_permissions(permission, payload)
            return f(payload, *args, **kwargs)

        return wrapper
    return requires_auth_decorator