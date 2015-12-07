'''
Check the performance counters from IIS
'''
#stdlib
from collections import namedtuple

# 3rd party
import wmi

# project
from checks import AgentCheck

WMIMetric = namedtuple('WMIMetric', ['name', 'value', 'tags'])

class IIS(AgentCheck):
    METRICS = [
        ('iis.uptime', 'gauge', 'ServiceUptime'),

        # Network
        ('iis.net.bytes_sent', 'rate', 'TotalBytesSent'),
        ('iis.net.bytes_rcvd', 'rate', 'TotalBytesReceived'),
        ('iis.net.bytes_total', 'rate', 'TotalBytesTransferred'),
        ('iis.net.num_connections', 'gauge', 'CurrentConnections'),
        ('iis.net.files_sent', 'rate', 'TotalFilesSent'),
        ('iis.net.files_rcvd', 'rate', 'TotalFilesReceived'),
        ('iis.net.connection_attempts', 'rate', 'TotalConnectionAttemptsAllInstances'),

        # HTTP Methods
        ('iis.httpd_request_method.get', 'rate', 'TotalGetRequests'),
        ('iis.httpd_request_method.post', 'rate', 'TotalPostRequests'),
        ('iis.httpd_request_method.head', 'rate', 'TotalHeadRequests'),
        ('iis.httpd_request_method.put', 'rate', 'TotalPutRequests'),
        ('iis.httpd_request_method.delete', 'rate', 'TotalDeleteRequests'),
        ('iis.httpd_request_method.options', 'rate', 'TotalOptionsRequests'),
        ('iis.httpd_request_method.trace', 'rate', 'TotalTraceRequests'),

        # Errors
        ('iis.errors.not_found', 'rate', 'TotalNotFoundErrors'),
        ('iis.errors.locked', 'rate', 'TotalLockedErrors'),

        # Users
        ('iis.users.anon', 'rate', 'TotalAnonymousUsers'),
        ('iis.users.nonanon', 'rate', 'TotalNonAnonymousUsers'),

        # Requests
        ('iis.requests.cgi', 'rate', 'TotalCGIRequests'),
        ('iis.requests.isapi', 'rate', 'TotalISAPIExtensionRequests'),
    ]
    SERVICE_CHECK = "iis.site_up"

    NAMESPACE = "root\\CIMV2"
    CLASS = "Win32_PerfFormattedData_W3SVC_WebService"

    def __init__(self, name, init_config, agentConfig, instances):
        AgentCheck.__init__(self, name, init_config, agentConfig, instances)
        self.wmi_conns = {}

    def _get_wmi_conn(self, host, user, password):
        key = "%s:%s:%s" % (host, user, password)
        if key not in self.wmi_conns:
            self.wmi_conns[key] = wmi.WMI(host, user=user, password=password)
        return self.wmi_conns[key]

    def check(self, instance):
        # Connect to the WMI provider
        host = instance.get('host', None)
        user = instance.get('username', None)
        password = instance.get('password', None)
        instance_tags = instance.get('tags', [])
        sites = instance.get('sites', ['_Total'])

        instance_key = "{host}:{namespace}:{class}".format(host, self.NAMESPACE, self.CLASS)
        properties = map(lambda x: x[2], self.METRICS)
        metrics_by_property = {}
        for metric, metric_type, prop in self.METRICS:
            metrics_by_property[prop] = (metric, metric_type)

        wmi_sampler = self._get_wmi_sampler(
            instance_key,
            self.CLASS, properties,
            filters=None,
            host=host, namespace=self.NAMESPACE,
            username=user, password=password
        )

        # Sample, extract & submit metrics
        wmi_sampler.sample()

        metrics = self._extract_metrics(wmi_sampler, instance_tags)

        self._submit_events(wmi_sampler, sites)
        self._submit_metrics(metrics, metrics_by_property)

    def _extract_metrics(self, wmi_sampler, sites, tags):
        """
        Extract and tag metrics from the WMISampler.

        Returns: List of WMIMetric
        ```
        [
            WMIMetric("freemegabytes", 19742, ["name:_total"]),
            WMIMetric("avgdiskbytesperwrite", 1536, ["name:c:"]),
        ]
        ```
        """
        metrics = []

        for wmi_obj in wmi_sampler:
            tags = list(tags) if tags else []

            # get site name
            sitename = wmi_obj['Name']

            # Skip any sites we don't specifically want.
            if sitename not in sites:
                continue
            elif sitename != "_Total":
                tags.append(sitename)

            # Tag with `tag_queries` parameter
            for wmi_property, wmi_value in wmi_obj.iteritems():
                # Tag with `tag_by` parameter
                try:
                    metrics.append(WMIMetric(wmi_property, float(wmi_value), tags + [sitename]))
                except ValueError:
                    self.log.warning(u"When extracting metrics with WMI, found a non digit value"
                                     " for property '{0}'.".format(wmi_property))
                    continue
                except TypeError:
                    self.log.warning(u"When extracting metrics with WMI, found a missing property"
                                     " '{0}'".format(wmi_property))
                    continue
        return metrics

    def _submit_events(self, wmi_sampler, sites):
        expected_sites = set(sites)

        for wmi_obj in wmi_sampler:
            sitename = wmi_obj['Name']
            if sitename == "_Total":
                continue

            uptime = wmi_obj["ServiceUptime"]
            if uptime == 0:
                status = AgentCheck.CRITICAL if uptime == 0 else AgentCheck.OK

            self.service_check("iis.site_up", status, tags=['site:%s' % sitename])
            expected_sites.remove(sitename)

        for site in expected_sites:
            self.service_check("iis.site_up", AgentCheck.CRITICAL, tags=['site:%s' % site])


    def _submit_metrics(self, wmi_metrics, metrics_by_property):
        for m in wmi_metrics:
            if m.name == "TotalBytesTransfered":
                m.name = "TotalBytesTransferred"
            elif m.name == "TotalConnectionAttemptsallinstances":
                m.name = "TotalConnectionAttemptsAllinstances"
            elif m.name not in metrics_by_property:
                continue

            metric, mtype = metrics_by_property[m.name]
            submittor = self.getattr(mtype)
            submittor(metric, m.value, m.tags)
