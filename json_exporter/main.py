#!/usr/bin/python
"""
Generic JSON HTTP(S) API exporter.
Based on
https://www.robustperception.io/writing-json-exporters-in-python/
https://www.robustperception.io/writing-a-jenkins-exporter-in-python/
"""
import argparse
import json
import jsonpath_ng.ext
import logging
import logging.config
import os
import re
import requests
import signal
import sys
import threading
import time
import yaml

from prometheus_client import start_http_server, Histogram, Counter
from prometheus_client.core import UntypedMetricFamily, GaugeMetricFamily, CounterMetricFamily, SummaryMetricFamily, HistogramMetricFamily, REGISTRY
from string import Template
from yaml.error import YAMLError

DEFAULT_LOG_CONFIG = """
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
"""
INVALID_METRIC_RE = re.compile(r'[^0-9a-zA-Z_:]')
LISTEN = "0.0.0.0"
MULTI_UNDERSCORE_RE = re.compile(r'_+')
NAN = float('NaN')
PORT = 8000
THREAD_JOIN_TIMEOUT = 1
TIMEOUT = 5
VERSION = '0.2.4'

# Create a metric to track time spent and requests made.
REQUEST_TIME = Histogram('json_exporter_collector_duration_seconds',
                         'Time spent collecting metrics from a target', ['name'])
ERROR_COUNTER = Counter('json_exporter_collector_error_count',
                        'Number of collector errors for a target', ['name'])


def debug(msg, *args):
    """Log debug message."""
    logging.debug(msg, *args)


def info(msg, *args):
    """Log info message."""
    logging.info(msg, *args)


def warn(msg, *args):
    """Log warning message."""
    logging.warning(msg, *args)


def error(msg, *args, **kwargs):
    """Log error message."""
    if kwargs.get('target'):
        ERROR_COUNTER.labels(kwargs.get('target')).inc()
    else:
        ERROR_COUNTER.inc()
    logging.error(msg, *args)


def fail(msg):
    """Print message and exit."""
    print(msg, file=sys.stderr)
    sys.exit(1)


def configure_logger(args, config):
    """Create logging"""
    log_config = {'version': 1}
    if 'logging' in config:
        log_config.update(config['logging'])
    else:
        log_config.update(yaml.safe_load(DEFAULT_LOG_CONFIG))

    logging.config.dictConfig(log_config)
    logger = logging.getLogger()
    if args.quiet:
        logger.setLevel(logging.WARNING)
    elif args.verbose:
        logger.setLevel(logging.DEBUG)


def parse_args():
    """Parse program arguments"""
    parser = argparse.ArgumentParser(
        description='export metrics from JSON HTTP(S) API endpoints (v{})'.format(VERSION))
    parser.add_argument("config", help='configuration file')
    parser.add_argument('-p', '--port', help='port to listen on (default {})'.format(PORT),
                        type=int, default=PORT)
    parser.add_argument('-l', '--listen', help='address to listen on (default "{}")'.format(LISTEN),
                        default=LISTEN)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-v", "--verbose", action="store_true")
    group.add_argument("-q", "--quiet", action="store_true")
    return parser.parse_args()


def load_config(filename):
    """Load YAML config from filename."""
    try:
        with open(filename) as config_file:
            config = yaml.safe_load(config_file)
    except (OSError, IOError) as exc:
        fail('could not open config file {} ({})'.format(filename, exc))
    except YAMLError as exc:
        fail('parse error in YAML configuration file {}:\n{}'.format(filename, exc))

    if not isinstance(config, dict):
        fail('invalid YAML configuration in file {}'.format(filename))

    return config


def render(tmpl, variables):
    """Render template tmpl with variables."""
    return Template(tmpl).safe_substitute(variables)


def get_metric_name(name):
    """Convert name into valid metric name."""
    return MULTI_UNDERSCORE_RE.sub('_', INVALID_METRIC_RE.sub('_', name))


class Rule(object):
    """Represent a single rule to collect metrics from a scraped JSON object."""

    def __init__(self, target_name, name, family, object_path, object_parser, metric_path, metric_parser,
                 static_label_keys, static_label_values, label_parsers, regex):
        self.target_name = target_name
        self.name = name
        self.family = family
        self.object_path = object_path
        self.object_parser = object_parser
        self.metric_path = metric_path
        self.metric_parser = metric_parser
        self.static_label_keys = static_label_keys
        self.static_label_values = static_label_values
        self.label_parsers = label_parsers
        self.regex = regex

    def __str__(self):
        return 'name=%s target=%s object_path=%s metric_path=%s static_label_keys=%r static_label_values=%r dynamic_labels=%r regex=%s' % (
            self.name,
            self.target_name,
            self.object_path,
            self.metric_path,
            self.static_label_keys,
            self.static_label_values,
            self.label_parsers.keys(),
            self.regex.pattern)

    def match_regex(self, path):
        """Return dictionary with regular expression groups from match on path."""
        m = self.regex.match(path)
        if m is not None:
            return m.groupdict()
        return {}

    def get_metrics(self, data):
        """Return metric matches and values from dictionary data."""
        for match in self.metric_parser.find(data):
            try:
                if match.value is None:
                    value = NAN
                else:
                    value = float(str(match.value))
            except ValueError:
                debug('target %s, rule %s, skipping value %s for path %s (not a number)',
                      self.target_name, self.name, match.value, match.full_path)
                continue
            yield match, value

    def get_dynamic_labels(self, obj):
        """Find all dynamic labels from jsonpath match obj."""
        if not self.label_parsers:
            return [], []
        dynamic_labels = {}
        for label in self.label_parsers:
            res = [match.value for match in self.label_parsers[label].find(obj)]
            if len(res) != 1:
                warn('target %s, rule %s, dynamic label "%s" returned %d matches instead of 1 for object path %s',
                     self.target_name, self.name, label, len(res), obj.full_path)
                dynamic_labels[label] = ""
            elif not isinstance(res[0], str):
                warn('target %s, rule %s, dynamic label "%s" returned non-string value %r for object path %s',
                     self.target_name, self.name, label, res[0], obj.full_path)
                dynamic_labels[label] = ""
            else:
                dynamic_labels[label] = res[0]
        dynamic_label_keys = sorted(dynamic_labels)
        dynamic_label_values = [dynamic_labels[label] for label in dynamic_label_keys]

        return dynamic_label_keys, dynamic_label_values

    def get_metric_families(self, data):
        """Return all Prometheus metric families extracted from dictionary data."""
        for obj in self.object_parser.find(data):
            cache = {}
            dynamic_label_keys, dynamic_label_values = self.get_dynamic_labels(obj)
            labels = tuple(self.static_label_keys + dynamic_label_keys)

            for match, value in self.get_metrics(obj):
                metric_path = str(match.full_path)
                re_variables = self.match_regex(metric_path)
                metric_name = get_metric_name(render(self.name, re_variables))
                debug('create metric_name %s from metric_path %s with value %s', metric_name, metric_path, value)
                metric_help = 'from %s' % metric_path
                key = tuple((metric_name, labels))
                if key not in cache:
                    cache[key] = self.family(metric_name, metric_help, labels=labels)

                label_values = [render(label, re_variables) for label in
                                self.static_label_values] + dynamic_label_values
                cache[key].add_metric(label_values, value)

            if len(cache) == 0:
                # assuming plain text as result and log it as that
                key = self.name
                if key not in cache:
                    cache[key] = self.family(self.name, self.name, labels=labels)
                cache[key].add_metric(self.static_label_values, data)

            for metric_name in cache:
                yield cache[metric_name]


class Target(object):
    """Represent a single target HTTP(S) endpoint to scrape JSON from."""

    def __init__(self, name, method, url, ttl, params, headers, body, timeout, ca_bundle, strftime, strftime_utc,
                 os_dependencies, transients):
        self.name = name
        self.method = method
        self.url = url
        self.url_ = url
        self.ttl = ttl
        self.params = str_params(params)
        self.headers = headers
        self.headers_ = headers.copy()
        self.body = body
        self.timeout = timeout
        self.session = requests.Session()
        # verify can also be set to ca_bundle file or directory
        # see http://docs.python-requests.org/en/master/user/advanced/#ssl-cert-verification
        self.session.verify = ca_bundle
        self.strftime = strftime
        self.strftime_utc = strftime_utc
        self.rules = []
        self.metric_families = []
        self.os_dependencies = os_dependencies
        self.transients = transients

    def __str__(self):
        return 'name=%s url=%s params=%r headers=%r timeout=%r' % (self.name,
                                                                   self.url,
                                                                   self.params,
                                                                   self.headers,
                                                                   self.timeout)

    def add_rule(self, rule):
        """Add a Rule object."""
        self.rules.append(rule)

    def run(self):
        """Scrape this target."""
        with REQUEST_TIME.labels(self.name).time():
            self.scrape()

    def get_metric_families(self):
        """Return collected metric families."""
        for family in self.metric_families:
            yield family

    def error(self, msg):
        """format error message with target name and url."""
        error('target {} at url {} {}'.format(self.name, self.url, msg), target=self.name)

    def render_expressions(self):
        """
        loop through every transient and check if TTL has expired from previous recorded time
        if so, re-evaluate transient and update both url and headers with potentially new updated values
        this is mostly useful for authentication tokens that may expire after a predetermined validity
        """
        current_time = time.time()
        evaluate = False
        for t in self.transients:
            transient = self.transients[t]
            if transient['ttl'] + transient['lastrun'] < current_time:
                debug('evaluating transient %s', t)
                evaluate = True
                transient['lastrun'] = current_time
                response = self.session.request(
                    transient['method'],
                    transient['url'],
                    params=read_from(transient, 'params', {}),
                    headers=read_from(transient, 'headers', {}),
                    data=json.dumps(read_from(transient, 'payload', {})),
                    timeout=self.timeout)
                transient['value'] = json.loads(response.text)[read_from(transient, 'json_response_data')]

        if evaluate:
            self.url = process_replacements(self.url_, self.os_dependencies, self.transients)
            for h in self.headers:
                self.headers[h] = process_replacements(self.headers_[h], self.os_dependencies, self.transients)

    def scrape(self):
        """Scrape the target and store metric families"""
        try:
            self.render_expressions()
            if self.strftime:
                if self.strftime_utc:
                    t = time.gmtime()
                else:
                    t = time.localtime()
                variables = {'strftime': time.strftime(self.strftime, t)}
                url = render(self.url, variables)
                params = {k: render(self.params[k], variables) for k in self.params}
                data = render(self.body, variables)
            else:
                url = self.url
                params = self.params
                data = self.body

            debug('scrape method=%s, url=%s, params=%r, headers=%r, data=%r', self.method, url, params, self.headers, data)
            response = self.session.request(self.method, url, params=params, headers=self.headers, data=data, timeout=self.timeout)
            response.raise_for_status()

            try:
                data = response.json()
            except ValueError:
                self.error('could not decode JSON response')
                return

            debug('scrape response=%r', data)
            self.metric_families = []
            for rule in self.rules:
                for family in rule.get_metric_families(data):
                    self.metric_families.append(family)
        except requests.HTTPError as exc:
            self.error('received unsuccessful response ({})'.format(exc))
        except requests.ConnectionError as exc:
            self.error('could not connect to url ({})'.format(exc))
        except requests.Timeout:
            self.error('connection timed out')
        except requests.TooManyRedirects:
            self.error('too many redirects')
        except requests.RequestException as exc:
            self.error('error in request ({})'.format(exc))


def str_params(params):
    """Stringify elements in param dict."""
    d = {}
    for k in params:
        if params[k] is None:
            d[k] = ""
        elif isinstance(params[k], list):
            d[k] = [str(i) for i in params[k]]
        else:
            d[k] = str(params[k])
    return d


def read_from(source, item, default=None):
    """Try to get item from source and return default if result is false."""
    return source.get(item) or default


def read_os_dependencies(source, item, default=None):
    """obtain system dependencies, useful mostly for secrets that should not be stored in a configuration file"""
    os_dependencies = {}
    config = read_from(source, item, default)
    for dependency in config:
        os_dependencies[dependency] = os.getenv(dependency.upper())
    return os_dependencies or default


def process_replacements(item, os_dependencies=None, transients=None):
    """processor for ${variables} in the configuration file itself, supports ${os_dependencies} and ${transients}"""
    if transients is None:
        transients = {}
    if os_dependencies is None:
        os_dependencies = {}
    replacements = re.findall(r'\$\{.*?}', item)
    for replacement in replacements:
        processed_replacement = replacement[2:-1]
        rtype = processed_replacement.split('.')[0]
        ritem = processed_replacement.split('.')[1]
        final_value = ''
        if rtype == 'os_dependencies':
            final_value = os_dependencies[ritem]
        if rtype == 'transients':
            final_value = transients[ritem]['value']

        debug('replacing "%s" into "%s"', ritem, item)
        item = item.replace(replacement, final_value)
    return item


def read_transients(source, item, os_dependencies, default=None):
    """Read transients from configuration file and set initial calculated values (such as last run time at zero)"""
    transients = {}
    config = read_from(source, item, default)
    for t in config:
        transient = config.get(t)
        transient['url'] = read_from(transient, 'url', '')
        transient['method'] = read_from(transient, 'method', 'GET')
        transient['ttl'] = read_from(transient, 'ttl', '3600')
        transient['payload'] = read_from(transient, 'payload', {})
        transient['json_response_data'] = read_from(transient, 'json_response_data', {})
        transient['lastrun'] = 0
        transient['value'] = ''

        for pl in transient['payload']:
            item = transient['payload'][pl]
            transient['payload'][pl] = process_replacements(item, os_dependencies)

        transients[t] = transient

    return transients or default


class JSONCollector(object):
    """Single JSON endpoint metric collector"""

    def __init__(self, config):
        self.targets = list(self.read_config(config))

    @staticmethod
    def read_target_config(target, glb_timeout, glb_ca_bundle, target_idx):
        """Read configuration items from target config."""
        target_name = read_from(target, 'name')
        method = read_from(target, 'method', 'GET')
        url = read_from(target, 'url')
        ttl = read_from(target, 'ttl')
        params = read_from(target, 'params', {})
        headers = read_from(target, 'headers', {})
        body = read_from(target, 'body', None)
        timeout = read_from(target, 'timeout', glb_timeout)
        ca_bundle = read_from(target, 'ca_bundle', glb_ca_bundle)
        strftime = read_from(target, 'strftime', '')
        strftime_utc = bool(read_from(target, 'strftime_utc', True))
        os_dependencies = read_os_dependencies(target, 'os_dependencies', {})
        transients = read_transients(target, 'transients', os_dependencies, {})
        if not target_name:
            warn('skipping target %d without a name', target_idx + 1)
            return None
        if not url:
            warn('skipping target %s without a url', target_name)
            return None
        return Target(target_name, method, url, ttl, params, headers, body, timeout, ca_bundle, strftime,
                      strftime_utc, os_dependencies, transients)

    @staticmethod
    def read_rule_config(rule, target_name, rule_idx):
        """Read configuration items from rule config."""
        rule_name = rule.get('name')
        metric_type = rule.get('metric_type', 'untyped')
        object_path = read_from(rule, 'object_path', '$')
        metric_path = read_from(rule, 'metric_path', '@..*')
        static_labels = read_from(rule, 'static_labels', {})
        dynamic_labels = read_from(rule, 'dynamic_labels', {})

        if not rule_name:
            warn('skipping target %s, rule %d without a name',
                 target_name, rule_idx + 1)
            return None

        try:
            object_parser = jsonpath_ng.ext.parse(object_path)
        except Exception as exc:
            warn('skipping target %s, rule %s with invalid object_path %s (%s)',
                 target_name, rule_name, object_path, exc)
            return None

        family = {'untyped': UntypedMetricFamily,
                  'counter': CounterMetricFamily,
                  'gauge': GaugeMetricFamily,
                  'summary': SummaryMetricFamily,
                  'histogram': HistogramMetricFamily
                  }.get(metric_type)
        if family is None:
            warn('skipping target %s, rule %s with invalid metric_type (%s)',
                 target_name, rule_name, metric_type)
            return None

        try:
            metric_parser = jsonpath_ng.ext.parse(metric_path)
        except Exception as exc:
            warn('skipping target %s, rule %s with invalid metric_path %s (%s)',
                 target_name, rule_name, metric_path, exc)
            return None

        static_label_keys = sorted(static_labels)
        static_label_values = [static_labels[label] for label in static_label_keys]
        label_parsers = {}
        for label in sorted(dynamic_labels):
            label_value = dynamic_labels[label]
            try:
                label_parsers[label] = jsonpath_ng.ext.parse(label_value)
            except Exception as exc:
                warn('skipping target %s, rule %s with invalid dynamic label %s=%s (%s)',
                     target_name, rule_name, label, label_value, exc)
                return None

        try:
            regex = re.compile(read_from(rule, 'regex', r'^$'))
        except Exception as exc:
            warn('skipping target %s, rule %s with invalid regex (%s)',
                 target_name, rule_name, exc)
            return None

        return Rule(target_name, rule_name, family,
                    object_path, object_parser, metric_path,
                    metric_parser, static_label_keys,
                    static_label_values, label_parsers, regex)

    def read_config(self, config):
        """Read configuration items from config."""
        glb_timeout = read_from(config, 'timeout', TIMEOUT)
        glb_ca_bundle = read_from(config, 'ca_bundle', True)
        for target_idx, target in enumerate(read_from(config, 'targets', [])):
            target_obj = self.read_target_config(target, glb_timeout, glb_ca_bundle, target_idx)
            if target_obj is None:
                continue
            info('configured target %s', target_obj)

            for rule_idx, rule in enumerate(read_from(target, 'rules', [])):
                rule = self.read_rule_config(rule, target_obj.name, rule_idx)
                if rule is None:
                    continue
                target_obj.add_rule(rule)

                info('configured rule %s', rule)

            yield target_obj

    def collect(self):
        """Collect Prometheus metric families from endpoints."""
        threads = []
        for target in self.targets:
            thread = threading.Thread(target=target.run, name=target.name)
            thread.start()
            threads.append(thread)

        done = False
        while not done:
            done = True
            for thread in threads:
                thread.join(THREAD_JOIN_TIMEOUT)
                if thread.is_alive():
                    done = False

        for target in self.targets:
            for metric_family in target.get_metric_families():
                yield metric_family


class Notifier(object):
    """Get notified about signals."""
    def __init__(self):
        self.terminate = False
        signal.signal(signal.SIGINT, self.handler)
        signal.signal(signal.SIGTERM, self.handler)
        signal.signal(signal.SIGHUP, self.handler)

    def handler(self, signum):
        """Handler for signals."""
        if signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            self.terminate = True


def main():
    """Main"""
    args = parse_args()
    config = load_config(args.config)
    configure_logger(args, config)
    info('starting app v{}'.format(VERSION))
    info("loaded config")
    debug("config:\n%r", config)

    notifier = Notifier()
    REGISTRY.register(JSONCollector(config))

    info('starting http server on {}:{}'.format(args.listen, args.port))
    start_http_server(args.port, args.listen)
    while not notifier.terminate:
        time.sleep(1)
    info('stopping http server on {}:{}'.format(args.listen, args.port))


if __name__ == '__main__':
    main()
