/*  =========================================================================
    autoconfig - Autoconfig

    Copyright (C) 2014 - 2018 Eaton

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
    =========================================================================
*/

#ifndef AUTOCONFIG_H_INCLUDED
#define AUTOCONFIG_H_INCLUDED

#include <map>
#include <string>
#include <list>
#include <malamute.h>

#define TIMEOUT 1000

struct AutoConfigurationInfo
{
    std::string type;
    std::string subtype;
    std::string operation;
    std::string update_ts;
    bool configured = false;
    uint64_t date = 0;
    std::map <std::string, std::string> attributes;
    bool operator==(fty_proto_t *message) const
    {
        bool bResult=true;
        bResult&=(operation==fty_proto_operation (message));
        bResult&=(type==fty_proto_aux_string (message, "type", ""));
        bResult&=(subtype==fty_proto_aux_string (message, "subtype", ""));
        //self is implicitly active, so we have to test it
        bResult&=(streq (fty_proto_aux_string (message, FTY_PROTO_ASSET_STATUS, "active"), "active"));
        if(!bResult)return false;
        
        //test all ext attributes
        std::map <std::string, std::string> msg_attributes=utils::zhash_to_map(fty_proto_ext (message));
        return attributes.size()== msg_attributes.size() &&
                std::equal(attributes.begin(), attributes.end(), msg_attributes.begin());
    };
};

void autoconfig (zsock_t *pipe, void *args);
void autoconfig_test (bool verbose);

class Autoconfig {
    public:
        explicit Autoconfig (const char *agentName) {_agentName = agentName; };
        explicit Autoconfig (const std::string &agentName) {_agentName = agentName; };
        virtual ~Autoconfig() {mlm_client_destroy (&_client); };

        static std::string StateFile; //!< file&path where Autoconfig state is saved
        static std::string StateFilePath; //!< fully-qualified path to dir where Autoconfig state is saved
        static std::string RuleFilePath; //!< fully-qualified path to dir where Autoconfig rule templates are saved
        static std::string AlertEngineName;
        const std::string getEname (const std::string &iname);

        int send( const char *subject, zmsg_t **msg_p ) { return mlm_client_send( _client, subject, msg_p ); };
        // replyto == sendto
        int sendto( const char *address, const char *subject, zmsg_t **send_p ) { return mlm_client_sendto( _client, address, subject, NULL, TIMEOUT, send_p ); };
        int sendfor( const char *address, const char *subject, zmsg_t **send_p ) { return mlm_client_sendfor( _client, address, subject, NULL, TIMEOUT, send_p ); };
        zmsg_t * recv( ) { return mlm_client_recv( _client ); };
        zmsg_t * recv_wait( int timeout )
        {
            if(!_client) {
                return NULL;
            }

            zsock_t *pipe = mlm_client_msgpipe(_client);
            if (!pipe) {
                return NULL;
            }

            zmsg_t *zmsg = NULL;
            zsock_t *which = NULL;
            zpoller_t *poller = zpoller_new(pipe, NULL);
            if (!poller) {
                return NULL;
            }

            which = (zsock_t *) zpoller_wait (poller, timeout);
            if (which) {
                zmsg = mlm_client_recv (_client);
            }
            zpoller_destroy (&poller);

            if (!zmsg) {
                return NULL;
            }
            return zmsg;
        }

        int set_producer( const char *stream ) { return mlm_client_set_producer( _client, stream ); };
        int set_consumer( const char *stream, const char *pattern ) { return mlm_client_set_consumer( _client, stream, pattern ); };
        const char * command( ) { return mlm_client_command( _client ); };
        int status( ) { return mlm_client_status( _client ); };
        const char * reason( ) { return mlm_client_reason( _client ); };
        const char * address( ) { return mlm_client_address( _client ); };
        const char * sender( ) { return mlm_client_sender( _client ); };
        const char * subject( ) { return mlm_client_subject( _client ); };
        zmsg_t * content( ) { return mlm_client_content( _client ); };
        zactor_t * actor( ) { return mlm_client_actor( _client ); };
        zsock_t * msgpipe( ) { return mlm_client_msgpipe( _client ); };
        mlm_client_t * client( ) { return  _client ; };

        void timeout(const int timeoutms) { _timeout = timeoutms; };
        int timeout() { return _timeout; };

        std::string agentName() { return _agentName; };
        void agentName(const std::string newname) { _agentName = newname; }
        void onStart () { loadState(); setPollingInterval(); };
        void onEnd ()   { cleanupState(); saveState(); };
        void onSend (fty_proto_t **message);
        virtual void onReply( zmsg_t **message ) { zmsg_destroy( message ); };
        void onPoll ();

        void main (zsock_t *pipe, char *name);
        bool connect(const char * endpoint, const char *stream = NULL,
                const char *pattern = NULL) {
            if( endpoint == NULL || _agentName.empty() ) return false;
            if( _client ) mlm_client_destroy( &_client );
            _client = mlm_client_new ();
            if ( _client == NULL ) return false;
            if (mlm_client_connect(_client, endpoint, TIMEOUT, _agentName.c_str ()) != 0) {
                        mlm_client_destroy (&_client);
                        return false;
            }

            if( stream ) {
                if( set_producer( stream ) < 0 ) {
                    mlm_client_destroy( &_client );
                    return false;
                }
                if( pattern ) {
                    if( set_consumer( stream, pattern ) < 0 ) {
                        mlm_client_destroy(&_client);
                        return false;
                    }
                }
            }
            return true;
        };
        void run(zsock_t *pipe, char *name) { onStart(); main(pipe, name); onEnd(); }
        bool compare(Autoconfig &self,fty_proto_t *message);
    private:
        void handleReplies( zmsg_t *message );
        void setPollingInterval();
        void cleanupState();
        void saveState();
        void loadState();
        std::map<std::string, AutoConfigurationInfo> _configurableDevices;
        // list of containers with their friendly names
        std::map<std::string, std::string> _containers; // iname | ename
        int64_t _timestamp;
    protected:
        mlm_client_t *_client = NULL;
        int _exitStatus = 0;
        int _timeout = 2000;
        std::string _agentName;
        std::list<std::string> getElemenListMatchTemplate(std::string template_name);
        void listTemplates(const char *correlation_id, const char *type);
};

#endif
