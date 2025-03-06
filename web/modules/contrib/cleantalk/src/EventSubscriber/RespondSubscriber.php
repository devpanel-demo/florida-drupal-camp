<?php

namespace Drupal\cleantalk\EventSubscriber;

use Drupal\cleantalk\CleantalkFuncs;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Sets extra headers on a successful response.
 */
class RespondSubscriber implements EventSubscriberInterface {

  /**
   * Gets the subscribed events.
   */
  public static function getSubscribedEvents(): array {
    $events[KernelEvents::RESPONSE][] = ['onRespond'];
    return $events;
  }

  /**
   * Sets extra headers on successful responses.
   *
   * @param $event
   *   The event to process.
   */
  public function onRespond($event) {
    if (\Drupal::config('cleantalk.settings')->get('cleantalk_check_external')
      && \Drupal::config('cleantalk.settings')->get('cleantalk_check_external__capture_buffer')) {
      $response = $event->getResponse();
      if ($response->getContent()) {
        $modifed_content = CleantalkFuncs::apbct_process_buffer($response->getContent(), $event->getRequest()->getPathInfo());
        $response->setContent($modifed_content);
      }
    }
  }

}
