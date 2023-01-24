# JSON exporter
This Prometheus exporter can be used to export metrics from a REST HTTP(S) API that provides JSON documents or 
outputs a single value. We use JSONPath (https://github.com/h2non/jsonpath-ng) to extract the metrics and regular 
expressions to extract tokens from a metric path and use it to create metric names and labels.

## Requirements
This module depends on:
 * requests
 * jsonpath_ng
 * PyYAML
 * prometheus_client

## Configuration file
The configuration file must be in YAML format. Here's an example:
```yaml
logging:
  root:
    level: INFO
    handlers:
      - console
  formatters:
    brief:
      format: "%(asctime)s %(levelname)s: %(message)s"
  handlers:
    console:
      class: logging.StreamHandler
      stream: ext://sys.stdout
      formatter: brief

targets:
  - name: logstash
    url: http://localhost:8080/logstash_node_stats.json
    headers:
      Host: www.example.com
      Authorization: Bearer ${transients.token}
    params:
      pretty: yes
    rules:
      - name: logstash_jvm_mem_pools_$metric
        object_path: $.jvm.mem.pools.*
        metric_path: "@.*"
        metric_type: gauge
        regex: jvm\.mem\.pools\.(?P<pool>[^.]+)\.(?P<metric>[^.]+)
        static_labels:
          pool: $pool
        dynamic_labels:
          name: $.name
      - name: logstash_jvm_mem_$metric
        object_path: $.jvm.mem.*
        metric_path: "@"
        metric_type: gauge
        regex: jvm\.mem\.(?P<metric>[^.]+)
        static_labels:
          foo: bar
        dynamic_labels:
          name: $.name
      - name: logstash_pipeline_events_$metric
        object_path: $.pipeline.events
        metric_path: "@.*"
        regex: pipeline\.events\.(?P<metric>[^.]+)
        dynamic_labels:
          name: $.name
      - name: logstash_all_$metric
        regex: (?P<metric>.*)
        dynamic_labels:
          name: $.name
      - name: logstash_test
    os_dependencies:
      - client_id
      - client_secret
    transients:
      token:
        method: POST
        url: https://account.auth0.com/oauth/token
        params:
          pretty: yes
        headers:
          content-type: application/json
        ttl: 10
        payload:
          client_id: ${os_dependencies.client_id}
          client_secret: ${os_dependencies.client_secret}
          audience: https://account.auth0.com/api/v2/
          grant_type: client_credentials
        json_response_data: access_token

  - name: auth0_total
    script:
      module: auth0_processor
      class: scrape_data
    timeout: 5
    params:
      base_url: https://account.auth0.com/api/v2/
      token: ${transients.token}
      requests_limit: 5

      # 1 hour - each auth0 request will be valid for this period
      requests_ttl: 36000

      # 2 years, give or take - a user is considered old when "last_login" surpasses this value
      old_threshold: 62208000

      # 1 week - a user is considered new when "created_at" subceeds this value
      new_threshold: 604800
    rules:
      - name: auth0_total_users
        object_path: $.connections[*]
        metric_path: "@.value"
        metric_type: gauge
        regex: connections\.\[(?P<id>.*)\]\.name(.*)\.context(.*)\.(?P<value>[^.]+)
        dynamic_labels:
          connection_id: "@.id"
          connection_name: "@.name"
          context: "@.context"
    os_dependencies:
      - client_id
      - client_secret
    transients:
      token:
        method: POST
        url: https://account.auth0.com/oauth/token
        headers:
          content-type: application/json
        ttl: 720
        payload:
          client_id: ${os_dependencies.client_id}
          client_secret: ${os_dependencies.client_secret}
          audience: https://account.auth0.com/api/v2/
          grant_type: client_credentials
        json_response_data: access_token

  - name: newrelic
    url: http://localhost:8080/servers.json
    timeout: 2
    rules:
      - name: newrelic_servers_summary_$metric
        object_path: $.servers[*]
        metric_path: "@.summary.*"
        metric_type: gauge
        regex: servers\.\[(?P<id>\d+)\]\.summary\.(?P<metric>[^.]+)
        dynamic_labels:
          name: "@.name"
          host: "@.host"
        static_labels:
          id: $id
```

### Global configuration
| item | description |
|------|-------------|
| `logging` | The `logging` section changes the default logger configuration (see https://docs.python.org/2/library/logging.config.html), optional |
| `targets` | The list of targets, optional |

### Targets
| item | description                                                                                                                                                                                                                                                                |
|------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `name` | name of the target, used in logging and exporter metrics                                                                                                                                                                                                                   |
| `method` | HTTP method to use when scraping target, defaults to GET, optional                                                                                                                                                                                                         |
| `url` | the target url to scrape metrics from                                                                                                                                                                                                                                      |
| `script` | support for complex processing that cannot be supported as a simple API query - replaces 'url' parameter                                                                                                                                                                   |
| `timeout` | the timeout to use, defaults to 5 seconds, optional                                                                                                                                                                                                                        |
| `params` | a mapping with query parameters to add to the url, optional                                                                                                                                                                                                                |
| `headers` | a mapping with HTTP headers to use when scraping target, optional                                                                                                                                                                                                          |
| `body` | data to use in message body when scraping target, optional                                                                                                                                                                                                                 |
| `strftime` | time format string https://docs.python.org/2/library/time.html#time.strftime, can be used as template variable in `url`, `params` and `body`, optional                                                                                                                     |
| `strtime_utc` | boolean to indicate if the time used in variable must be in UTC, defaults to `yes`, optional                                                                                                                                                                               |
| `ca_bundle` | a certificate file name or OpenSSL `c_rehash` processed directory, optional                                                                                                                                                                                                |
| `os_dependencies` | a list of system variables that should be obtained from the underlying OS or container and that can be referenced in this configuration file as ${os_dependencies.\<item in the array\>}, optional                                                                         |
| `transients` | array containing items required for either the url or the headers that have a time to live after wich should be considered expired and have to be reavaluated via a request and that can be referenced in this configuration file as ${transients.\<transient\>}, optional |

### Transients
| item                 | description                                                                                                                            |
|----------------------|----------------------------------------------------------------------------------------------------------------------------------------|
| `url`                | the target url to retrieve the transient value from                                                                                    |
| `method`             | HTTP method to use when retrieving the transient value, defaults to GET, optional                                                      |
| `params`             | a mapping with query parameters to add to the url, optional                                                                            |
| `headers`            | a mapping with HTTP headers to use when retrieving the transient value, optional                                                       |
| `ttl`                | time-to-live of the transient in minutes, after expired the transient value will be re-fetched and all the related values re-evaluated |
| `payload`            | http body request to send, can refer to os_dependencies                                                                                |
| `json_response_data` | value in the json response that will be retrieved and used as value when th transient is referred to                                   |

### Rules
| item | description                                                                                                                                                                                                                                            |
|------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `name` | name of the rule, can contain variables like `$metric` or `${metric}` which are substituted with group matches from the `regex` expression.                                                                                                            |
| `object_path` | a JSONPath expression to select the initial objects from the JSON object, optional                                                                                                                                                                     |
| `metric_path` | a JSONPath expression to select the metrics starting from the selected `object_path`, but can be relative (using `@`) or absolute (using `$`), optional                                                                                                |
| `metric_type` | sets the type of the metric. Possible types are `untyped`, `gauge`, `counter`, `summary` and `histogram`. defaults to `untyped`                                                                                                                        |
| `regex` | a regular expression used to extract values ("groups") from a metric_path. These values are inserted in template variables into rule names or static labels, optional                                                                                  |
| `dynamic_labels` | key-value pairs that are added to a metric. The value of this label is determined dynamically with a JSONPath expression and must yield a single string value, optional                                                                                |
| `static_labels` | key-value pairs that are added to a metric. The value of this label is determined by inserting template values (variables must start with a `$` or be enclosed with `${` and `}`). For example using variables like `$metric` or `${metric}`, optional |
