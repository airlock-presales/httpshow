"""
HttpShow: Simple HTTP server to return request details in html

Copyright 2018-2025 Urs Zurbuchen

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and 
associated documentation files (the “Software”), to deal in the Software without restriction, 
including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, 
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial
portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT
LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH 
THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""

#---------------------------------------------------------------------------
#   Module imports
#---------------------------------------------------------------------------
import logging
import os
import yaml

#---------------------------------------------------------------------------
#   Miscellaneous module data
#---------------------------------------------------------------------------
CONFIGFILE = '/opt/httpshow/config.yaml'

#---------------------------------------------------------------------------
#   Configuration settings
#---------------------------------------------------------------------------
class Settings( object ):
    
    """
    Settings
    """

    # internals
    
    def __init__( self, configfile: str=None, settings: dict=None ):
        """
        Constructor
        """
        if settings != None:
            self._settings = settings
            self._configfile = None
        else:
            self._settings = None
            if configfile == None or configfile == '':
                self._configfile = os.getenv( "HTTPSHOW_CONFIG_FILE", CONFIGFILE )
            else:
                self._configfile = configfile
            if self._configfile == "":
                self._configfile = None
        self._logger = logging.getLogger(__name__)
        _log_level = os.getenv("HTTPSHOW_LOG_LEVEL", "warning")
        if _log_level.lower() == "debug":
            self.log_level = 10
        elif _log_level.lower() == "info":
            self.log_level = 20
        elif _log_level.lower() == "warning":
            self.log_level = 30
        elif _log_level.lower() == "error":
            self.log_level = 40
        elif _log_level.lower() == "critical":
            self.log_level = 50
        self._logger.setLevel( self.log_level )
        self.load()
        self.port = self.get( "HTTPSHOW_SERVER_PORT", "server.port", default=8000, data_type="int" )
        self.app_secret_key = self.get( "HTTPSHOW_APP_SECRET_KEY", "httpshow.appSecret", default="" )
        self.oidc_issuer = self.get( "HTTPSHOW_OIDC_ISSUER", "oidc.issuer" )
        self.oidc_client_id = self.get( "HTTPSHOW_OIDC_CLIENT_ID", "oidc.client.id" )
        self.oidc_client_secret = self.get( "HTTPSHOW_OIDC_CLIENT_SECRET", "oidc.client.secret" )
        self.oidc_client_timeout = self.get( "HTTPSHOW_OIDC_TIMEOUT", "oidc.client.timeout", data_type="int" )
        scopes = self.get( "HTTPSHOW_OIDC_SCOPES", "oidc.scopes", default=[] )
        if isinstance(scopes, list):
            self.oidc_scope = " ".join( scopes )
        else:
            self.oidc_scope = scopes
        self.pkce = self.get( "HTTPSHOW_OIDC_PKCE", "oidc.pkce", default=True, data_type="bool" )
        self.par = self.get( "HTTPSHOW_OIDC_PAR", "oidc.par", default=False, data_type="bool" )
        self.userinfo = self.get( "HTTPSHOW_OIDC_USERINFO", "oidc.userInfo", default=False, data_type="bool" )
        self.verify_provider_certificate = self.get( "HTTPSHOW_OIDC_VERIFY_PROVIDER_CERTIFICATE", "oidc.verifyProviderCertificate", default=True, data_type="bool" )
        self.base_url = self.get( "HTTPSHOW_BASE_URL", "server.baseURL", default="http://localhost" )
        self.session_cookie_name = self.get( "HTTPSHOW_SESSION_COOKIE_NAME", "httpshow.session.cookieName", default="httpshow" )
        self.session_lifetime = self.get( "HTTPSHOW_SESSION_LIFETIME", "httpshow.session.lifetime", default=300, data_type="int" )
        self.trust_proxy_headers = self.get( "HTTPSHOW_TRUST_PROXY_HEADERS", "server.trustProxyHeaders", default=False, data_type="bool" )
        self.trusted_proxies = self.get( "HTTPSHOW_TRUSTED_PROXIES", "server.trustedProxies", default=[] )
        self.css_file = self.get( "HTTPSHOW_CSS_FILE", "httpshow.cssFile", default="/opt/httpshow/style.css" )
        self.night_mode = self.get( "HTTPSHOW_NIGHT_MODE", "httpshow.nightMode", default=False, data_type="bool" )

    def __repr__( self ) -> str:
        return "Settings: %s" % (self._settings)
    
    ## actions
    def load( self, src: str=None ) -> bool:
        if src == None:
            if self._configfile == None:
                return
            try:
                fp = open( self._configfile, "rb" )
            except FileNotFoundError:
                return False
        else:
            fp = src
        try:
            self._settings = yaml.safe_load( fp )
        except:
            return False
        if src == None:
            fp.close()
        return True
    
    ## get settings values
    def get( self, env: str, path: str, default: str=None, data_type: str=None ) -> any:
        value = os.getenv( env )
        if value == None:
            if self._settings != None and path != None:
                value = self.select( path )
        if value == None:
            value = default
        if data_type == "bool" and isinstance(value, str):
            if value.lower() == "true":
                value = True
            elif value.lower() == "false":
                value = False
            else:
                self._logger.warning(f"Config: invalid data type for {env} = {value} - replaced with default {default}")
                value = default
        elif data_type == "int" and isinstance(value, str):
            try:
                value = int(value)
            except ValueError:
                self._logger.warning(f"Config: invalid data type for {env} = {value} - replaced with default {default}")
                value = default
        self._logger.debug(f"Load config: {env} = {value}")
        return value
    
    def select( self, path: str ) -> any:
        if self._settings == None:
            return None
        area = self._settings
        for key in path.split( '.' ):
            try:
                area = area[key]
            except (KeyError, TypeError):
                return None
        return area
    
    ## getter/setter
    def get_logLevel( self ):
        return self.log_level
    
    def get_configfile( self ):
        return int( self._configfile )
    
    def dump( self, log, level ):
        if log == None:
            print( "Configfile: %s" % (self._configfile,) )
            print( "- log-level: %s" % (self.log_level,) )
        else:
            log.log( level, "Configfile: %s" % (self._configfile,) )
            log.log( level, "- log-level: %s" % (self.log_level,) )
    
