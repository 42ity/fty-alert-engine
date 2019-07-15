/*  =========================================================================
    fty-alert-engine - Daemon evaluating rules and producing alerts

    Copyright (C) 2019 - 2019 Eaton

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

/*
@header
    fty-alert-engine - Daemon evaluating rules and producing alerts
@discuss
@end
*/

#include "fty_alert_engine_classes.h"

int main (int argc, char *argv [])
{
    std::string log_config_file = "";
    std::string rule_location = "";
    std::string template_location = "";
    std::string timeout_config = "";
    zconfig_t *cfg = NULL;
    ManageFtyLog::setInstanceFtylog ("fty-alert-engine");

    int argn;
    for (argn = 1 ; argn < argc; argn++)
    {
        char *par = NULL;
        if (argn < argc -1)
            par = argv [argn + 1];

        if (streq (argv [argn], "-v") ||
            streq (argv [argn], "--verbose")) {
            ManageFtyLog::getInstanceFtylog ()->setVeboseMode ();
        }
        else if (streq (argv [argn], "-h") ||
                 streq (argv [argn], "--help")) {
            puts ("fty-alert-engine [option] [value]");
            puts ("   -v|--verbose          verbose output");
            puts ("   -h|--help             print help");
            puts ("   -c|--config [path]    use custom config file ");
            return 0;
        }
        else if (streq (argv [argn], "-c") ||
                 streq (argv [argn], "--config")) {
            if (par)
                cfg = zconfig_load (par);
            ++argn;
        }
        else {
            printf ("Unknown option: %s, run with -h|--help \n", argv [argn]);
            return 1;
        }
    }

    if (!cfg) {
        cfg = zconfig_load (CONFIG_FILE);
    }

    log_config_file = std::string (zconfig_get (cfg, "log/config", FTY_COMMON_LOGGING_DEFAULT_CFG));
    rule_location = std::string (zconfig_get (cfg, "server/rules", RULE_PATH_DEFAULT));
    template_location = std::string (zconfig_get (cfg, "server/templates", TEMPLATE_PATH_DEFAULT));
    timeout_config = std::string (zconfig_get (cfg, "server/timeout", DEFAULT_TIMEOUT));

    //If a log config file is configured, try to load it
    if (!log_config_file.empty ())
    {
      ManageFtyLog::getInstanceFtylog ()->setConfigFile (log_config_file);
    }

    // trigger
    zactor_t *agent_trigger_stream = zactor_new (fty_alert_trigger_stream_main, (void*) TRIGGER_AGENT_NAME_STREAM);
    zactor_t *agent_trigger_mailbox = zactor_new (fty_alert_trigger_mailbox_main, (void*) TRIGGER_AGENT_NAME_MAILBOX);
    // trigger mailbox
    zstr_sendx (agent_trigger_mailbox, "CONFIG", rule_location.c_str (), NULL);
    zstr_sendx (agent_trigger_mailbox, "CONNECT", ENDPOINT, NULL);
    zstr_sendx (agent_trigger_mailbox, "TIMEOUT", std::to_string (fty_get_polling_interval () * 1000).c_str (), NULL);
    zstr_sendx (agent_trigger_mailbox, "ALERT_LIST_MB_NAME", LIST_AGENT_NAME, NULL); // trigger mailbox name
    zstr_sendx (agent_trigger_mailbox, "PRODUCER", FTY_PROTO_STREAM_ALERTS_SYS, NULL); // due to TOUCH mailbox
    zstr_sendx (agent_trigger_mailbox, "LOAD_PERSISTENCE", NULL); // due to TOUCH mailbox
    // trigger stream + alert evaluation
    zstr_sendx (agent_trigger_stream, "CONNECT", ENDPOINT, NULL);
    zstr_sendx (agent_trigger_stream, "TIMEOUT", std::to_string (fty_get_polling_interval () * 1000).c_str (), NULL);
    zstr_sendx (agent_trigger_stream, "PRODUCER", FTY_PROTO_STREAM_ALERTS_SYS, NULL);
    //zstr_sendx (agent_trigger_stream, "CONSUMER", FTY_PROTO_STREAM_METRICS, ".*", NULL); // disabled in favor of SHM
    zstr_sendx (agent_trigger_stream, "CONSUMER", FTY_PROTO_STREAM_METRICS_UNAVAILABLE, ".*", NULL);
    zstr_sendx (agent_trigger_stream, "CONSUMER", FTY_PROTO_STREAM_METRICS_SENSOR, "status.*", NULL);
    zstr_sendx (agent_trigger_stream, "CONSUMER", FTY_PROTO_STREAM_LICENSING_ANNOUNCEMENTS, ".*", NULL);

    // config (both MB and stream as there is no need for great responsivenes)
    zactor_t *agent_config = zactor_new (fty_alert_config_main, (void*) CONFIG_AGENT_NAME);
    zstr_sendx (agent_config, "CONNECT", ENDPOINT, NULL);
    zstr_sendx (agent_config, "TIMEOUT", timeout_config.c_str (), NULL);
    zstr_sendx (agent_config, "TEMPLATES_DIR", template_location.c_str (), NULL); // rule template
    zstr_sendx (agent_config, "CONSUMER", FTY_PROTO_STREAM_ASSETS, ".*", NULL);
    zstr_sendx (agent_config, "ALERT_TRIGGER_MB_NAME", TRIGGER_AGENT_NAME_MAILBOX, NULL); // trigger mailbox name
    zstr_sendx (agent_config, "SEND_RULE", "warranty.rule", NULL);

    //  Accept and print any message back from server
    //  copy from src/malamute.c under MPL license
    while (true) {
        char *messageS = zstr_recv (agent_trigger_stream);
        if (messageS) {
            puts (messageS);
            free (messageS);
        } else {
            log_info ("interrupted");
            break;
        }

        char *messageM = zstr_recv (agent_trigger_mailbox);
        if (messageM) {
            puts (messageM);
            free (messageM);
        } else {
            log_info ("interrupted");
            break;
        }
    }

    // TODO save info to persistence before I die
    zactor_destroy (&agent_trigger_stream);
    zactor_destroy (&agent_trigger_mailbox);
    zactor_destroy (&agent_config);
    return 0;
}
