<?php

namespace Drupal\cleantalk\EventSubscriber;

use Cleantalk\Common\Mloader\Mloader;
use Drupal\cleantalk\CleantalkFuncs;
use Drupal\Component\Utility\Html;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\HttpKernel\Event\RequestEvent;

if (!defined('APBCT_TBL_FIREWALL_DATA'))
  define('APBCT_TBL_FIREWALL_DATA', 'cleantalk_sfw');      // Table with firewall data.
if (!defined('APBCT_TBL_FIREWALL_LOG'))
  define('APBCT_TBL_FIREWALL_LOG',  'cleantalk_sfw_logs'); // Table with firewall logs.
if (!defined('APBCT_TBL_AC_LOGS'))
  define('APBCT_TBL_AC_LOGS',        'cleantalk_ac_logs');   // Table with firewall logs.
if (!defined('APBCT_TBL_AC_UA_BL'))
  define('APBCT_TBL_AC_UA_BL',      'cleantalk_ua_bl');    // Table with User-Agents blacklist.
if (!defined('APBCT_TBL_SESSIONS'))
  define('APBCT_TBL_SESSIONS',      'cleantalk_sessions'); // Table with session data.
if (!defined('APBCT_SPAMSCAN_LOGS'))
  define('APBCT_SPAMSCAN_LOGS',     'cleantalk_spamscan_logs'); // Table with session data.
if (!defined('APBCT_SELECT_LIMIT'))
  define('APBCT_SELECT_LIMIT',      5000); // Select limit for logs.
if (!defined('APBCT_WRITE_LIMIT'))
  define('APBCT_WRITE_LIMIT',       5000); // Write limit for firewall data.

class RequestSubscriber implements EventSubscriberInterface {

  public static function getSubscribedEvents(): array {
    $events[KernelEvents::REQUEST][] = ['onRequest'];
    return $events;
  }

  public function onRequest(RequestEvent $event) {
    global $cleantalk_executed;

    $request = $event->getRequest();
    $curr_user = \Drupal::currentUser();

    // Exclusion. Administrator.
    if ($curr_user->hasPermission('access administration menu') || $cleantalk_executed) {
      return;
    }

    // Exclusion. By roles.
    $roles = \Drupal::config('cleantalk.settings')->get('cleantalk_roles_exclusions');
    if (!empty($roles)) {
      foreach ($roles as $role_id) {
        if (CleantalkFuncs::_cleantalk_user_has_role_id($role_id, $curr_user)) {
          return;
        }
      }
    }

    $route = \Drupal::routeMatch()->getRouteObject();
    $is_admin = \Drupal::service('router.admin_context')->isAdminRoute($route);

    if ($is_admin) {
      return;
    }

    // If Cookies are enabled and headers not sent
    if (\Drupal::config('cleantalk.settings')->get('cleantalk_set_cookies') && ! headers_sent()) {

      // Cookie names to validate
      $cookie_test_value = array(
        'cookies_names' => array(),
        'check_value' => trim(\Drupal::config('cleantalk.settings')->get('cleantalk_authkey')),
      );

      // Submit time
      $apbct_timestamp = time();
      // Fix for submit_time = 0
      if (\Drupal::config('cleantalk.settings')->get('cleantalk_alternative_cookies_session')) {
        // by database
        $prev_time = CleantalkFuncs::apbct_getcookie('apbct_prev_timestamp');
        if (is_null($prev_time)) {
          CleantalkFuncs::apbct_setcookie('apbct_timestamp', $apbct_timestamp);
          CleantalkFuncs::apbct_setcookie('apbct_prev_timestamp', $apbct_timestamp);
          $cookie_test_value['check_value'] .= $apbct_timestamp;
        } else {
          CleantalkFuncs::apbct_setcookie('apbct_timestamp', $prev_time);
          CleantalkFuncs::apbct_setcookie('apbct_prev_timestamp', $apbct_timestamp);
          $cookie_test_value['check_value'] .= $prev_time;
        }
      } else {
        // by cookies
        CleantalkFuncs::apbct_setcookie('apbct_timestamp', $apbct_timestamp);
        $cookie_test_value['check_value'] .= $apbct_timestamp;
      }
      $cookie_test_value['cookies_names'][] = 'apbct_timestamp';

      //Previous referer
      if (!empty($_SERVER['HTTP_REFERER'])) {
        CleantalkFuncs::apbct_setcookie('apbct_prev_referer', $_SERVER['HTTP_REFERER']);
        $cookie_test_value['cookies_names'][] = 'apbct_prev_referer';
        $cookie_test_value['check_value'] .= $_SERVER['HTTP_REFERER'];
      }

      // Cookies test
      $cookie_test_value['check_value'] = md5($cookie_test_value['check_value']);
      CleantalkFuncs::apbct_setcookie('apbct_cookies_test', json_encode($cookie_test_value));

    } // ENDIF: If Cookies are enabled and headers not sent

    // Remote calls
    /** @var \Cleantalk\Common\RemoteCalls\RemoteCalls $rc_class */
    $rc_class = Mloader::get('RemoteCalls');
    /** @var \Cleantalk\Common\StorageHandler\StorageHandler $storage_handler */
    $storage_handler = Mloader::get('StorageHandler');
    if ($rc_class::check()) {
      $remote_calls = new $rc_class(trim(\Drupal::config('cleantalk.settings')->get('cleantalk_authkey')), new $storage_handler());
      try {
          die ($remote_calls->process());
      } catch ( \Cleantalk\Common\RemoteCalls\Exceptions\RemoteCallsException $exception ) {
          die ('FAIL ' . json_encode(array('error' => $exception->getMessage())));
      }
    }

    //Custom Contact forms
    if (count($_POST) > 0 && !$request->get('form_build_id') && !$request->get('form_id') && \Drupal::config('cleantalk.settings')->get('cleantalk_check_ccf')) {

      /** @var \Cleantalk\Common\Helper\Helper $helper_class */
      $helper_class = MLoader::get('Helper');
      $ct_temp_msg_data = $helper_class::get_fields_any($request->request->all());
      $spam_check = array();
      $spam_check['type'] = 'custom_contact_form';
      $spam_check['sender_email'] = ($ct_temp_msg_data['email']    ? $ct_temp_msg_data['email']    : '');
      $spam_check['sender_nickname'] = ($ct_temp_msg_data['nickname'] ? $ct_temp_msg_data['nickname'] : '');
      $spam_check['message_title'] = ($ct_temp_msg_data['subject']  ? $ct_temp_msg_data['subject']  : '');
      $spam_check['message_body'] = ($ct_temp_msg_data['message']  ? implode("\n", $ct_temp_msg_data['message'])  : '');

      if ($spam_check['sender_email'] != '' || $spam_check['message_title'] != '' || $spam_check['message_body'] != '') {

        $result = CleantalkFuncs::_cleantalk_check_spam($spam_check);

        if (isset($result) && is_array($result) && $result['errno'] == 0 && $result['allow'] != 1) {
          \Drupal::messenger()->addError(HTML::escape($result['ct_result_comment']));
        }
      }
    }

    // Search
    if ($request->server->get('REQUEST_URI') && strpos($request->server->get('REQUEST_URI'), 'search') !== false && $request->get('keys')) {

      if (\Drupal::config('cleantalk.settings')->get('cleantalk_check_search_form')) {
        global $user;
        $get_query = $request->get('keys');
        $spam_check['type'] = 'site_search_drupal9';
        $spam_check['sender_email'] = !empty($user->mail) ? $user->mail : '';
        $spam_check['sender_nickname'] = !empty($user->name) ? $user->name : '';
        $spam_check['message_title'] = '';
        $spam_check['message_body'] = $get_query;

        if ($spam_check['sender_email'] != '' || $spam_check['message_body']) {
          $spam_result = CleantalkFuncs::_cleantalk_check_spam($spam_check);

          if (isset($spam_result) && is_array($spam_result) && $spam_result['errno'] == 0 && $spam_result['allow'] != 1)
            CleantalkFuncs::_cleantalk_die($spam_result['ct_result_comment']);
        }
      }
    }

    // External Forms
    if (
      count( $_POST ) > 0 &&
      \Drupal::config('cleantalk.settings')->get('cleantalk_check_external') &&
      $request->get( 'cleantalk_hidden_method' ) &&
      $request->get( 'cleantalk_hidden_action' )
    ) {
      $action = htmlspecialchars( $request->get( 'cleantalk_hidden_action' ) );
      $method = htmlspecialchars( $request->get( 'cleantalk_hidden_method' ) );
      $request->request->remove( 'cleantalk_hidden_action' );
      $request->request->remove( 'cleantalk_hidden_method' );

      /** @var \Cleantalk\Common\Helper\Helper $helper_class */
      $helper_class = MLoader::get('Helper');
      $ct_temp_msg_data = $helper_class::get_fields_any($request->request->all());
      $spam_check = array();
      $spam_check['type'] = 'external_form';
      $spam_check['sender_email'] = ($ct_temp_msg_data['email']    ? $ct_temp_msg_data['email']    : '');
      $spam_check['sender_nickname'] = ($ct_temp_msg_data['nickname'] ? $ct_temp_msg_data['nickname'] : '');
      $spam_check['message_title'] = ($ct_temp_msg_data['subject']  ? $ct_temp_msg_data['subject']  : '');
      $spam_check['message_body'] = ($ct_temp_msg_data['message']  ? implode("\n", $ct_temp_msg_data['message'])  : '');

      if ($spam_check['sender_email'] != '' || $spam_check['message_title'] != '' || $spam_check['message_body'] != '') {

        $result = CleantalkFuncs::_cleantalk_check_spam( $spam_check );
        if (isset($result) && is_array($result) && $result['errno'] == 0 && $result['allow'] != 1) {
          // Do block
          CleantalkFuncs::ct_die(HTML::escape($result['ct_result_comment']));
        } else {
          // Do the form sending
          if (! $request->isXmlHttpRequest()) {
            print "<html><body><form method='$method' action='$action'>";
            CleantalkFuncs::print_form($_POST, '');
            print "</form></body></html>";
            print "<script " . ( class_exists('Cookiebot_WP') ? 'data-cookieconsent="ignore"' : '' ) . ">
              if(document.forms[0].submit !== 'undefined'){
                var objects = document.getElementsByName('submit');
                if(objects.length > 0)
                  document.forms[0].removeChild(objects[0]);
              }
              document.forms[0].submit();
            </script>";
            die();
          }
        }
      }
    }
  }
}
