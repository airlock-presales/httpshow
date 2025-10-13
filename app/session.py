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
import time
from uuid import uuid4


class SessionData( object ):
    def __init__( self, cfg, session_id: str, data: dict={} ):
        self.id = session_id
        self.user_id = None
        self.email = None
        self.name = None
        self._cfg = cfg
        self._data = {}
        self._logger = logging.getLogger(__name__)
        self._logger.setLevel(self._cfg.log_level)
        if self._cfg.session_lifetime > 0:
            self._expires = time.time() + self._cfg.session_lifetime
        else:
            self._expires = 0
        self._valid = True
        self.store( data )
    
    def __repr__( self ) -> str:
        r = self.getUser()
        r.update( self._data )
        return str( r )
    
    def getId( self ) -> str:
        return self.get( "id" )
    
    def isValid( self ) -> bool:
        return self._valid
    
    def isExpired( self, now ) -> bool:
        if self._expires <= now:
            return True
        self._valid = False
        return False
    
    def getUser( self ) -> dict:
        return {
            "user_id": self.getUserId(),
            "email": self.getEmail(),
            "name": self.getName()
        }
    
    def getUserId( self ) -> str:
        return self.get( "user_id" )
    
    def getEmail( self ) -> str:
        return self.get( "email" )
    
    def getName( self ) -> str:
        return self.get( "name" )
    
    def get( self, key, default: any=None ) -> str:
        # if self.isValid():
        #     return default
        if self._cfg.session_lifetime > 0:
            self._expires = time.time() + self._cfg.session_lifetime
        if key == "id":
            return self.id
        elif key == "user_id":
            return self.user_id
        elif key == "email":
            return self.email
        elif key == "name":
            return self.name
        else:
            try:
                return self._data[key]
            except KeyError:
                return default
    
    def set( self, key, value ):
        if key == "user_id":
            self.user_id = value
        elif key == "email":
            self.email = value
        elif key == "name":
            self.name = value
        else:
            self._data[key] = value
        self._logger.debug(f"Session: {key} = {value}")
    
    def store( self, data: dict=None ):
        if data != None:
            for key, value in data.items():
                self.set( key, value )
    
    def delete( self, key ):
        if key == "user_id":
            self.user_id = None
        elif key == "email":
            self.email = None
        elif key == "name":
            self.name = None
        else:
            try:
                del self._data[key]
            except KeyError:
                pass


class SessionStore( object ):
    def __init__( self, cfg ):
        self._cfg = cfg
        self._sessions = {}
        self._next_cleanup = 0
        self._cleanup( time.time() )
        # print( f"Cleanup @ {self._next_cleanup}" )
    
    def create( self, data: dict={} ) -> SessionData:
        now = time.time()
        if now > self._next_cleanup:
            self._cleanup( now )
        session_id = str(uuid4())
        while session_id in self._sessions:
            session_id = str(uuid4())
        self._sessions[session_id] = SessionData( self._cfg, session_id, data )
        return self._sessions[session_id]
    
    def find( self, session_id: str ) -> SessionData:
        if session_id == None:
            return None
        now = time.time()
        if now > self._next_cleanup:
            self._cleanup( now )
        try:
            return self._sessions[session_id]
        except KeyError:
            return None
    
    def delete( self, session_id: str ):
        try:
            del self._sessions[session_id]
        except KeyError:
            pass
    
    def _cleanup( self, now ):
        # print( f"Cleanup: {now} - {self._next_cleanup}" )
        keys = []
        for key in self._sessions.keys():
            keys.append( key )
        for session_id in keys:
            session_data = self._sessions[session_id]
            if session_data.isExpired( now ):
                del self._sessions[session_id]
                continue
        # for session_id, session_data in self._sessions.items():
        #     if session_data.isExpired( now ):
        #         del self._sessions[session_id]
        #         continue
        self._next_cleanup = now + 300
    
