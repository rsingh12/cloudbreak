package com.sequenceiq.periscope.monitor;

import java.util.List;
import java.util.concurrent.ExecutorService;

import org.quartz.JobDataMap;
import org.quartz.JobExecutionContext;
import org.quartz.JobExecutionException;
import org.springframework.context.ApplicationContext;

import com.sequenceiq.periscope.api.model.ClusterState;
import com.sequenceiq.periscope.domain.Cluster;
import com.sequenceiq.periscope.log.MDCBuilder;
import com.sequenceiq.periscope.monitor.evaluator.EvaluatorExecutor;
import com.sequenceiq.periscope.service.ClusterService;

public abstract class AbstractMonitor implements Monitor {

    private ClusterService clusterService;

    private ApplicationContext applicationContext;

    private ExecutorService executorService;

    @Override
    public void execute(JobExecutionContext context) throws JobExecutionException {
        MDCBuilder.buildMdcContext();
        evalContext(context);
        for (Cluster cluster : getClusters()) {
            EvaluatorExecutor evaluatorExecutor = applicationContext.getBean(getEvaluatorType().getSimpleName(), EvaluatorExecutor.class);
            evaluatorExecutor.setContext(getContext(cluster));
            executorService.submit(evaluatorExecutor);
        }
    }

    void evalContext(JobExecutionContext context) {
        JobDataMap monitorContext = context.getJobDetail().getJobDataMap();
        applicationContext = (ApplicationContext) monitorContext.get(MonitorContext.APPLICATION_CONTEXT.name());
        executorService = applicationContext.getBean(ExecutorService.class);
        clusterService = applicationContext.getBean(ClusterService.class);
    }

    ClusterService getClusterService() {
        return clusterService;
    }

    List<Cluster> getClusters() {
        return clusterService.findAll(ClusterState.RUNNING, true);
    }
}
