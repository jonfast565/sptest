from urllib.parse import urlparse
from flask import Flask, request, Response, redirect
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.utils import OneLogin_Saml2_Utils

app = Flask(__name__)
settings_path = "./"


def prepare_from_flask_request(request):
    url_data = urlparse(request.url)
    return {
        'http_host': request.host,
        'server_port': url_data.port,
        'script_name': request.path,
        'get_data': request.args.copy(),
        'post_data': request.form.copy()
    }


@app.route('/')
def main_page():
    return 'Main Page. Use /sso /acs /slo and /md endpoints to test this SP.'


@app.route('/sso', methods = ['GET'])
def sp():
    req = prepare_from_flask_request(request)
    auth = OneLogin_Saml2_Auth(req, custom_base_path=settings_path)
    login = auth.login()
    return redirect(login)


@app.route('/acs', methods = ['POST', 'GET'])
def acs():
    req = prepare_from_flask_request(request)
    auth = OneLogin_Saml2_Auth(req, custom_base_path=settings_path)
    auth.process_response()
    errors = auth.get_errors()
    if not errors:
        if auth.is_authenticated():
            request.session['samlUserdata'] = auth.get_attributes()
            if 'RelayState' in req['post_data'] and \
                    OneLogin_Saml2_Utils.get_self_url(req) != req['post_data']['RelayState']:
                auth.redirect_to(req['post_data']['RelayState'])
            else:
                result = ""
                for attr_name in request.session['samlUserdata'].keys():
                    result += format('%s ==> %s' % (attr_name, '|| '.join(request.session['samlUserdata'][attr_name])))
                return result
        else:
            return 'Not authenticated'
    else:
        return format("Error when processing SAML Response: %s" % (', '.join(errors)))


@app.route('/md')
def md():
    req = prepare_from_flask_request(request)
    auth = OneLogin_Saml2_Auth(req, custom_base_path=settings_path)
    saml_settings = auth.get_settings()
    metadata = saml_settings.get_sp_metadata()
    errors = saml_settings.validate_metadata(metadata)
    if len(errors) == 0:
        return Response(metadata, mimetype='text/xml')
    else:
        return format("Error found on Metadata: %s" % (', '.join(errors)))


if __name__ == '__main__':
    app.run(debug=True)
