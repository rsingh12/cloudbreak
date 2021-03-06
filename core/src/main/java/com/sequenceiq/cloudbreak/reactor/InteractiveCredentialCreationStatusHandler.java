package com.sequenceiq.cloudbreak.reactor;

import java.util.Date;

import javax.inject.Inject;

import org.springframework.stereotype.Component;

import com.sequenceiq.cloudbreak.api.model.CloudbreakEventsJson;
import com.sequenceiq.cloudbreak.cloud.event.credential.InteractiveCredentialCreationStatus;
import com.sequenceiq.cloudbreak.converter.spi.ExtendedCloudCredentialToCredentialConverter;
import com.sequenceiq.cloudbreak.reactor.api.event.EventSelectorUtil;
import com.sequenceiq.cloudbreak.reactor.handler.ReactorEventHandler;
import com.sequenceiq.cloudbreak.service.notification.Notification;
import com.sequenceiq.cloudbreak.service.notification.NotificationSender;

import reactor.bus.Event;

/**
 * Created by perdos on 9/23/16.
 */
@Component
public class InteractiveCredentialCreationStatusHandler implements ReactorEventHandler<InteractiveCredentialCreationStatus> {

    @Inject
    private NotificationSender notificationSender;

    @Inject
    private ExtendedCloudCredentialToCredentialConverter extendedCloudCredentialToCredentialConverter;

    @Override
    public String selector() {
        return EventSelectorUtil.selector(InteractiveCredentialCreationStatus.class);
    }

    @Override
    public void accept(Event<InteractiveCredentialCreationStatus> interactiveCredentialCreationFailedEvent) {
        InteractiveCredentialCreationStatus interactiveCredentialCreationStatus = interactiveCredentialCreationFailedEvent.getData();
        String message = interactiveCredentialCreationStatus.getMessage();
        CloudbreakEventsJson notification = new CloudbreakEventsJson();
        if (interactiveCredentialCreationStatus.isError()) {
            notification.setEventType("CREDENTIAL_CREATE_FAILED");
        } else {
            notification.setEventType("INTERACTIVE_CREDENTIAL_STATUS");
        }
        notification.setEventTimestamp(new Date().getTime());
        notification.setEventMessage(message);
        notification.setOwner(interactiveCredentialCreationStatus.getCloudContext().getOwner());
        notification.setAccount(interactiveCredentialCreationStatus.getExtendedCloudCredential().getAccount());
        notification.setCloud(interactiveCredentialCreationStatus.getExtendedCloudCredential().getCloudPlatform());
        notificationSender.send(new Notification<>(notification));
    }
}
