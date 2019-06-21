# fty-alert-engine

Agent fty-alert-engine is the main component for evaluating metrics and publishing pure alerts.
These are then processed by fty-alert-list, which takes care of resolving and acknowledging alerts.

## How to build

To build fty-alert-engine project run:

```bash
./autogen.sh
./configure
make
make check # to run self-test
```

## How to run

To run fty-alert-engine project:

* from within the source tree, run:

```bash
./src/fty-alert-engine
```

For the other options available, refer to the manual page of fty-alert-engine

* from an installed base, using systemd, run:

```bash
systemctl start fty-alert-engine
```

### Configuration file

Configuration file - fty-alert-engine.cfg - is currently ignored.
Agent reads environment variable BIOS\_LOG\_LEVEL, which sets verbosity level.

Rules loaded at start up are stored in the directory /var/lib/fty/fty-alert-engine/.

### Rule types

Rules are currently of types flexible, single, pattern and threshold, refer to templates for more details
Major differences and use cases:
* pattern rule don't require assets, and uses metrics as regex patterns - asset is determined by matching a metric name
by metric, always runs LUA evaluation
* threshold accepts multiple metrics and either compare values of one metric to values list (hardcoded names
low_warning, low_critical, high_warning, high_critical) or aggregates multiple metrics via LUA function and return
respective result
* single accepts specified metrics for one asset, but always runs LUA evaluation (difference to threshold)
* flexible supports string variables (other accept just doubles), runs LUA evaluation for specified metrics, is supposed
to work with multiple assets (never used so far, not tested), metrics are evaluated as metric@asset for every asset in
list

### Rule templates

Rules are currently of types flexible, single, pattern and threshold
UPPERCASEs are variables to be filled
lowercases are fixed
// comments are to put more details, not part of json format
one|other means OR operator, provided either one or other applies
... means more might follow
{
    "single|pattern|threshold|flexible" : {
        "name" : "NAME",
        "description" : "DESCRIPTION", // optional
        "class" : "CLASS", // optional
        "categories" : [ // nonempty
            "CAT1", "CAT2", ...
        ],
        "metrics" : "METRIC"|[ // can be either value or array, nonempty
            "METRIC1", "METRIC2", ...
        ],
        "results" : [ // nonempty
            {
                "RES1" : { // this object is called outcome
                    "action" : [ // can be empty
                        {"action" : "EMAIL|SMS"},
                        { "action" : "GPO_INTERACTION", "asset" : "ASSET", "mode" : "MODE"},
                        ...
                    ],
                    "description" : "DESCRIPTION",
                    "threshold_name" : "THRESHOLD_NAME",
                    "severity" : "SEVERITY"
                }
            },
            ...
        ],
        "source" : "SOURCE", // optional
        "assets" : "ASSET"|[ // can be either value or array, can be empty (pattern rule)
            "ASSET1", "ASSET2", ...
        ],
        "outcome_item_count" : "OUTCOME_ITEM_COUNT", // optional
        "values" : [ // can be empty
            { "VAR1NAME" : "VAR1VALUE" }, { "VAR2NAME" : "VAR2VALUE" }, ...
        ],
        "values_unit" : "VALUES_UNIT",
        "hierarchy" : "hierarchy",
        "models" : [ // optional, flexible only
            "MODEL1", "MODEL2", ...
        ]
    }
}

## Architecture

### Overview

fty-alert-engine is composed of 2 actors:

* fty-alert-trigger: keeps alert rule persistence, triggers alerts based on metrics
* fty-alert-config: on asset creation/delete, processes templates and creates rules for given asset

## Protocols

### Published metrics

Agent doesn't publish any metrics.

### Published alerts

Agent publishes alerts on \_ALERTS\_SYS stream.

### Mailbox requests

Actor fty-alert-trigger can be requested for:

* list of rules
* getting rule content
* adding new rule
* updating rule
* touching rule (forces re-evaluation)
* deleting rules

Actor fty-alert-config server can be requested for:
 * list of templates
 * addition of template
 * passing rule to the rest of alert agents

#### List of rules

The USER peer sends the following messages using MAILBOX SEND to
FTY-ALERT-TRIGGER ("fty-alert-trigger") peer:

* LIST/'type'\[/'ruleclass'\]

where
* '/' indicates a multipart string message
* 'type' MUST be one of the values: 'all','threshold','single','pattern','flexible'
* 'ruleclass' MAY be any string (even empty)
* subject of the message MUST be 'rfc-evaluator-rules'

The FTY-ALERT-TRIGGER peer MUST respond with one of the messages back to USER
peer using MAILBOX SEND.

* LIST/'type'/'ruleclass'/'rule\-1'/.../'rule\-n'
* ERROR/'reason'

where
* '/' indicates a multipart frame message
* 'type' MUST be copied from the request
* 'ruleclass' MUST be copied from the request (empty string if it was empty)
* 'rule\-1',...'rule\-n' MUST be JSONs corresponding to rules of given type and rule class
* 'reason' is string detailing reason for error. Possible values are: INVALID\_TYPE
* subject of the message MUST be 'rfc-evaluator-rules'

#### Getting rule content

The USER peer sends the following messages using MAILBOX SEND to
FTY-ALERT-TRIGGER ("fty-alert-trigger") peer:

* GET/'name'

where
* '/' indicates a multipart string message
* 'name' MUST be name of the rule
* subject of the message MUST be 'rfc-evaluator-rules'

The FTY-ALERT-TRIGGER peer MUST respond with one of the messages back to USER
peer using MAILBOX SEND.

* OK/'rule'
* ERROR/'reason'

where
* '/' indicates a multipart frame message
* 'rule' MUST be JSON corresponding to the rule 'name'
* 'reason' is string detailing reason for error. Possible values are: NOT\_FOUND
* subject of the message MUST be 'rfc-evaluator-rules'

#### Adding new rule

The USER peer sends the following messages using MAILBOX SEND to
FTY-ALERT-TRIGGER ("fty-alert-trigger") peer:

* ADD/'rule'

where
* '/' indicates a multipart string message
* 'rule' MUST be valid JSON for the rule of the kind handled by fty-alert-trigger
* subject of the message MUST be 'rfc-evaluator-rules'

The FTY-ALERT-TRIGGER peer MUST respond with one of the messages back to USER
peer using MAILBOX SEND.

* OK/'rule'
* ERROR/reason

where
* '/' indicates a multipart frame message
* 'rule' MUST be JSON copied from request
* 'reason' is string detailing reason for error. Possible values are:
    * ALREADY\_EXISTS
    * BAD\_LUA
    * Internal error \- operating with storage/disk failed.
    * BAD\_JSON
* subject of the message MUST be 'rfc-evaluator-rules'

#### Updating rule

The USER peer sends the following messages using MAILBOX SEND to
FTY-ALERT-TRIGGER ("fty-alert-trigger") peer:

* ADD/'rule'/'old\-name'

where
* '/' indicates a multipart string message
* 'rule' MUST be valid JSON for the rule of the kind handled by fty-alert-trigger (as opposed to fty-alert-flexible)
* 'old\-name' MUST be name of the existing rule
* subject of the message MUST be 'rfc-evaluator-rules'

The FTY-ALERT-TRIGGER peer MUST respond with one of the messages back to USER
peer using MAILBOX SEND.

* OK/'rule'
* ERROR/reason

where
* '/' indicates a multipart frame message
* 'rule' MUST be JSON copied from request
* 'reason' is string detailing reason for error. Possible values are:
    * NOT\_FOUND
    * ALREADY\_EXISTS
    * BAD\_LUA
    * Internal error \- operating with storage/disk failed.
    * BAD\_JSON
* subject of the message MUST be 'rfc-evaluator-rules'

#### Touching rule

The USER peer sends the following messages using MAILBOX SEND to
FTY-ALERT-TRIGGER ("fty-alert-trigger") peer:

* TOUCH/'name'

where
* '/' indicates a multipart string message
* 'name' MUST be name of an existing rule
* subject of the message MUST be 'rfc-evaluator-rules'

The FTY-ALERT-TRIGGER peer MUST respond with one of the messages back to USER
peer using MAILBOX SEND.

* OK
* ERROR/reason

where
* '/' indicates a multipart frame message
* 'reason' is string detailing reason for error. Possible values are: NOT\_FOUND
* subject of the message MUST be 'rfc-evaluator-rules'

#### Deleting rules

To delete one particular rule, the USER peer sends the following messages using MAILBOX SEND to
FTY-ALERT-TRIGGER ("fty-alert-trigger") peer:

* DELETE/'name'

where
* '/' indicates a multipart string message
* 'name' MUST be name of an existing rule

The FTY-ALERT-TRIGGER peer MUST respond with one of the messages back to USER
peer using MAILBOX SEND.

* OK/rulename1/rulename2/...
* ERROR/reason

To delete all rules about an element, the USER peer sends the following messages using MAILBOX SEND to
FTY-ALERT-TRIGGER ("fty-alert-trigger") peer:

* DELETE_ELEMENT/'name'

where
* '/' indicates a multipart string message
* 'name' MUST be a known element with rules attached

The FTY-ALERT-TRIGGER peer MUST respond with one of the messages back to USER
peer using MAILBOX SEND.

* OK/rulename1/rulename2/...
* ERROR/reason

#### List of templates rules

The USER peer sends the following messages using MAILBOX SEND to 
FTY-ALERT-CONFIG ("fty-alert-config") peer:

* LIST/'correlation_id'/['filter']

where
* '/' indicates a multipart string message
* 'filter' is a regex matching the content : typical regex are 'threshold','single','pattern','flexible'
           "all" means return all templates. filter is optional, by default "all" is applied
* subject of the message MUST be 'rfc-evaluator-rules'

The FTY-ALERT-CONFIG peer MUST respond with one of the messages back to USER
peer using MAILBOX SEND.

* 'correlation_id'/LIST/'filter'/
    'template-name-1'/'template-1'/'device-iname-comma-separator-list-1'
    ../../..
    'template-name-n'/'template-n'/'device-iname-comma-separator-list-n'
* 'correlation_id'/ERROR/'reason'

where
* '/' indicates a multipart frame message
* 'filter' MUST be copied from the request
* 'rule\-1',...'rule\-n' MUST be JSONs corresponding to rules of given type and rule class
* 'reason' is string detailing reason for error. Possible values are: INVALID\_FILTER
* subject of the message MUST be 'rfc-evaluator-rules'

### Stream METRICS\_UNAVAILABLE

This stream is used to signal that certain metric is no longer available (for example because corresponding asset was
removed).

Every message on the stream METRICS\_UNAVAILABLE MUST be of the format METRICUNAVAILABLE/<topic>.

### Stream subscriptions

Actor fty-alert-trigger is subscribed to streams METRICS, METRICS\_UNAVAILABLE and METRICS\_SENSOR, and to SHM shared
memory of metrics.
On each stream message it stores message to cache, which gets evaluated based on periodic timer.
On periodic timer trigger it does the following:
* Resolves all alerts for unavailable metrics.
* Evaluates all rules based on metric cache and SHM, clears cache.

Actor fty-alert-config is subscribed to stream ASSETS and on each ASSET message, it updates asset cache.

