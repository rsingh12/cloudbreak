package com.sequenceiq.periscope.api.model;

import java.util.List;

import com.sequenceiq.periscope.doc.ApiDescription.ClusterJsonsProperties;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;

@ApiModel("AutoscaleClusterRequest")
public class AutoscaleClusterRequest extends ClusterBaseJson {

    @ApiModelProperty(ClusterJsonsProperties.PASSWORD)
    private String pass;

    @ApiModelProperty(ClusterJsonsProperties.ENABLE_AUTOSCALING)
    private boolean enableAutoscaling;

    @ApiModelProperty(ClusterJsonsProperties.METRIC_ALERTS)
    private List<MetricAlertRequest> metricAlerts;

    @ApiModelProperty(ClusterJsonsProperties.TIME_ALERTS)
    private List<TimeAlertRequest> timeAlerts;

    @ApiModelProperty(ClusterJsonsProperties.PROMETHEUS_ALERTS)
    private List<PrometheusAlertRequest> prometheusAlerts;

    @ApiModelProperty(ClusterJsonsProperties.SCALING_CONFIGURATION)
    private ScalingConfigurationRequest scalingConfiguration;

    public AutoscaleClusterRequest() {
    }

    public AutoscaleClusterRequest(String host, String port, String user, String pass, Long stackId, boolean enableAutoscaling) {
        super(host, port, user, stackId);
        this.pass = pass;
        this.enableAutoscaling = enableAutoscaling;
    }

    public String getPass() {
        return pass;
    }

    public void setPass(String pass) {
        this.pass = pass;
    }

    public boolean enableAutoscaling() {
        return enableAutoscaling;
    }

    public void setEnableAutoscaling(boolean enableAutoscaling) {
        this.enableAutoscaling = enableAutoscaling;
    }

    public List<MetricAlertRequest> getMetricAlerts() {
        return metricAlerts;
    }

    public void setMetricAlerts(List<MetricAlertRequest> metricAlerts) {
        this.metricAlerts = metricAlerts;
    }

    public List<TimeAlertRequest> getTimeAlerts() {
        return timeAlerts;
    }

    public void setTimeAlerts(List<TimeAlertRequest> timeAlerts) {
        this.timeAlerts = timeAlerts;
    }

    public List<PrometheusAlertRequest> getPrometheusAlerts() {
        return prometheusAlerts;
    }

    public void setPrometheusAlerts(List<PrometheusAlertRequest> prometheusAlerts) {
        this.prometheusAlerts = prometheusAlerts;
    }

    public ScalingConfigurationRequest getScalingConfiguration() {
        return scalingConfiguration;
    }

    public void setScalingConfiguration(ScalingConfigurationRequest scalingConfiguration) {
        this.scalingConfiguration = scalingConfiguration;
    }
}
