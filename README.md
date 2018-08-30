# fty-alert-engine

Agent fty-alert-engine is the main component for evaluating metrics and publishing pure alerts.
These are then processed by fty-alert-list, which takes care of resolving and acknowledging alerts.

NB: Rules for fty-alert-engine have strictly defined format. Agents which need different kinds of rules use fty-alert-flexible for alert publishing.

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

To be added.

### Rule templates

To be added.

## Architecture

### Overview

fty-alert-engine is composed of 3 actors and 2 timers:

* fty-alert-engine-server: does general alert management
* fty-autoconfig: on asset creation/update, processes templates and creates rules for given asset
* fty-autoconfig-timer (implicit): runs each \_timeout (default value 2 seconds); checks asset cache and creates template-based rules for assets
* fty-alert-actions: takes care of alert notification using email/SMS/GPO activation
* fty-alert-actions-timer (implicit): runs every minute; deletes timed-out alerts and checks whether to send e-mail/SMS based on severity and priority

## Protocols

### Published metrics

Agent doesn't publish any metrics.

### Published alerts

Agent publishes alerts on \_ALERTS\_SYS stream.

### Mailbox requests

Actor fty-alert-engine server can be requested for:

* list of rules
* getting rule content
* adding new rule
* updating rule
* touching rule (forces re-evaluation)
* deleting rules

Actor fty-autoconfig server can be requested for:
 * list of templates

Actor fty-alert-actions doesn't receive any mailbox requests.

#### List of rules

The USER peer sends the following messages using MAILBOX SEND to
FTY-ALERT-ENGINE-SERVER ("fty-alert-engine") peer:

* LIST/'type'\[/'ruleclass'\]

where
* '/' indicates a multipart string message
* 'type' MUST be one of the values: 'all','threshold','single','pattern'
* 'ruleclass' MAY be any string (even empty)
* subject of the message MUST be 'rfc-evaluator-rules'

The FTY-ALERT-ENGINE-SERVER peer MUST respond with one of the messages back to USER
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
FTY-ALERT-ENGINE-SERVER ("fty-alert-engine") peer:

* GET/'name'

where
* '/' indicates a multipart string message
* 'name' MUST be name of the rule
* subject of the message MUST be 'rfc-evaluator-rules'

The FTY-ALERT-ENGINE-SERVER peer MUST respond with one of the messages back to USER
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
FTY-ALERT-ENGINE-SERVER ("fty-alert-engine") peer:

* ADD/'rule'

where
* '/' indicates a multipart string message
* 'rule' MUST be valid JSON for the rule of the kind handled by fty-alert-engine-server (as opposed to fty-alert-flexible)
* subject of the message MUST be 'rfc-evaluator-rules'

The FTY-ALERT-ENGINE-SERVER peer MUST respond with one of the messages back to USER
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
FTY-ALERT-ENGINE-SERVER ("fty-alert-engine") peer:

* ADD/'rule'/'old\-name'

where
* '/' indicates a multipart string message
* 'rule' MUST be valid JSON for the rule of the kind handled by fty-alert-engine-server (as opposed to fty-alert-flexible)
* 'old\-name' MUST be name of the existing rule
* subject of the message MUST be 'rfc-evaluator-rules'

The FTY-ALERT-ENGINE-SERVER peer MUST respond with one of the messages back to USER
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
FTY-ALERT-ENGINE-SERVER ("fty-alert-engine") peer:

* TOUCH/'name'

where
* '/' indicates a multipart string message
* 'name' MUST be name of an existing rule
* subject of the message MUST be 'rfc-evaluator-rules'

The FTY-ALERT-ENGINE-SERVER peer MUST respond with one of the messages back to USER
peer using MAILBOX SEND.

* OK
* ERROR/reason

where
* '/' indicates a multipart frame message
* 'reason' is string detailing reason for error. Possible values are: NOT\_FOUND
* subject of the message MUST be 'rfc-evaluator-rules'

#### Deleting rules

To delete one particular rule, the USER peer sends the following messages using MAILBOX SEND to
FTY-ALERT-ENGINE-SERVER ("fty-alert-engine") peer:

* DELETE/'name'

where
* '/' indicates a multipart string message
* 'name' MUST be name of an existing rule

The FTY-ALERT-ENGINE-SERVER peer MUST respond with one of the messages back to USER
peer using MAILBOX SEND.

* OK/rulename1/rulename2/...
* ERROR/reason

To delete all rules about an element, the USER peer sends the following messages using MAILBOX SEND to
FTY-ALERT-ENGINE-SERVER ("fty-alert-engine") peer:

* DELETE_ELEMENT/'name'

where
* '/' indicates a multipart string message
* 'name' MUST be a known element with rules attached

The FTY-ALERT-ENGINE-SERVER peer MUST respond with one of the messages back to USER
peer using MAILBOX SEND.

* OK/rulename1/rulename2/...
* ERROR/reason

#### List of templates rules

The USER peer sends the following messages using MAILBOX SEND to 
FTY-AUTOCONFIG-SERVER ("fty-autoconfig") peer:

* LIST/'correlation_id'/['filter']

where
* '/' indicates a multipart string message
* 'filter' is a regex matching the content : typical regex are 'threshold','single','pattern'
           "all" means return all templates. filter is optional, by default "all" is applied
* subject of the message MUST be 'rfc-evaluator-rules'

The FTY-AUTOCONFIG-SERVER peer MUST respond with one of the messages back to USER
peer using MAILBOX SEND.

* LIST/'correlation_id'/'filter'/'rule\-1'/.../'rule\-n'
* ERROR/'correlation_id'/'reason'

where
* '/' indicates a multipart frame message
* 'filter' MUST be copied from the request
* 'rule\-1',...'rule\-n' MUST be JSONs corresponding to rules of given type and rule class
* 'reason' is string detailing reason for error. Possible values are: INVALID\_FILTER
* subject of the message MUST be 'rfc-evaluator-rules'

### Stream METRICS\_UNAVAILABLE

This stream is used to signal that certain metric is no longer available (for example because corresponding asset was removed).

Every message on the stream METRICS\_UNAVAILABLE MUST be of the format METRICUNAVAILABLE/<topic>.

### Stream subscriptions

Actor fty-alert-engine-server is subscribed to streams METRICS, METRICS\_UNAVAILABLE and METRICS\_SENSOR.
On each METRIC message, it updates metric cache, removes old metrics (older than their TTL) and re-evaluates all rules dependent on this metric.
On each METRICUNAVAILABLE message, it finds all the rules dependent on this metric and resolves all the alerts triggered by them. For each found rule, it sends back a response message from TOUCH protocol.

Actor fty-autoconfig is subscribed to stream ASSETS and on each ASSET message, it updates asset cache.

Actor fty-alert-actions is subscribed to streams ASSETS and ALERTS.
On each ASSET message, it updates asset cache.
On each ALERT message, it updates alert cache.

