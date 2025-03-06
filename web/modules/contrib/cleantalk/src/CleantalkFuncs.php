<?php

namespace Drupal\cleantalk;

//Antispam classes
use Cleantalk\Common\Mloader\Mloader;
use Cleantalk\Common\Variables\Post;
use Cleantalk\Custom\Antispam\Cleantalk;
use Cleantalk\Custom\Antispam\CleantalkRequest;

//Common classes
use Cleantalk\Custom\Helper\Helper as CleantalkHelper;
use Cleantalk\Common\Firewall\Firewall;
use Cleantalk\Common\Variables\Server;



use Symfony\Component\HttpKernel\Exception\ServiceUnavailableHttpException;

// Sessions
if (!defined('APBCT_SESSION__LIVE_TIME')) {
  define('APBCT_SESSION__LIVE_TIME', 86400 * 2);
}
if (!defined('APBCT_SESSION__CHANCE_TO_CLEAN')) {
  define('APBCT_SESSION__CHANCE_TO_CLEAN', 100);
}

if (!defined('APBCT_TBL_FIREWALL_DATA')) {
  define(
    'APBCT_TBL_FIREWALL_DATA',
    'cleantalk_sfw'
  );      // Table with firewall data.
}
if (!defined('APBCT_TBL_FIREWALL_LOG')) {
  define(
    'APBCT_TBL_FIREWALL_LOG',
    'cleantalk_sfw_logs'
  ); // Table with firewall logs.
}
if (!defined('APBCT_TBL_AC_LOGS')) {
  define(
    'APBCT_TBL_AC_LOGS',
    'cleantalk_ac_logs'
  );   // Table with firewall logs.
}
if (!defined('APBCT_TBL_AC_UA_BL')) {
  define(
    'APBCT_TBL_AC_UA_BL',
    'cleantalk_ua_bl'
  );    // Table with User-Agents blacklist.
}
if (!defined('APBCT_TBL_SESSIONS')) {
  define(
    'APBCT_TBL_SESSIONS',
    'cleantalk_sessions'
  ); // Table with session data.
}
if (!defined('APBCT_SPAMSCAN_LOGS')) {
  define(
    'APBCT_SPAMSCAN_LOGS',
    'cleantalk_spamscan_logs'
  ); // Table with session data.
}
if (!defined('APBCT_SELECT_LIMIT')) {
  define('APBCT_SELECT_LIMIT', 5000); // Select limit for logs.
}
if (!defined('APBCT_WRITE_LIMIT')) {
  define('APBCT_WRITE_LIMIT', 5000); // Write limit for firewall data.
}

/**
 * Cleantalk class create request
 */
class CleantalkFuncs
{
  public static $version = '9.5.0';

  /**
  * get form submit_time
  */
  public static function _cleantalk_get_submit_time($timestamp) {
    return self::_cleantalk_apbct_cookies_test() == 1 && $timestamp ? time(
      ) - (int) $timestamp : NULL;
  }

  /**
   * Save our variables into cookies OR sessions
   *
   * @param $name  string   Name of our variables to save
   * @param $value string   Value of our variables to save
   */
  public static function apbct_setcookie($name, $value) {
    if (\Drupal::config('cleantalk.settings')->get('cleantalk_set_cookies')) {
      if (\Drupal::config('cleantalk.settings')->get(
        'cleantalk_alternative_cookies_session'
      )) {
        self::_apbct_alt_sessions__remove_old();

        /** @var \Cleantalk\Common\Db\Db $db_class */
        $db_class = Mloader::get('Db');
        $db_obj = $db_class::getInstance();

        // Into database
        $connection = \Drupal::database();
        $query = $db_obj->altCookiesStoreQuery('cleantalk_sessions');
        $connection->query($query,
          [
             ':id' => self::_apbct_alt_session__id__get(
             ),
             ':name' => $name,
             ':value' => $value,
             ':last_update' => date(
               'Y-m-d H:i:s'
             ),
           ]
        );
      }
      else {
        $secure = !in_array(Server::get('HTTPS'), ['off', '']
          ) || (int) Server::get('SERVER_PORT') === 443;

        // For PHP 7.3+ and above
        if (version_compare(phpversion(), '7.3.0', '>=')) {
          $params = [
            'expires' => 0,
            'path' => '/',
            'secure' => $secure,
            'httponly' => FALSE,
            'samesite' => 'lax',
          ];

          setcookie($name, $value, $params);
          // For PHP 5.6 - 7.2
        }
        else {
          setcookie($name, $value, 0, '/', '', $secure, 'lax');
        }
      }
    }
  }

  /**
   * Get our variables from cookies OR sessions
   *
   * @param $name string    Name of necessary variable to get
   *
   * @return string|null
   */
  public static function apbct_getcookie($name) {
    if (\Drupal::config('cleantalk.settings')->get('cleantalk_set_cookies')) {
      if (\Drupal::config('cleantalk.settings')->get(
          'cleantalk_alternative_cookies_session'
        )
        && ((strpos($name, 'apbct') === 0)
          || (strpos($name, 'ct') === 0)
        )
      ) {
        // From database
        $connection = \Drupal::database();
        $value = $connection->query(
          "SELECT value FROM {cleantalk_sessions} WHERE id = :id AND name = :name",
          [
            ':id' => self::_apbct_alt_session__id__get(),
            ':name' => $name,
          ]
        )->fetchField();
        if (FALSE !== $value) {
          return $value;
        }
        else {
          return NULL;
        }
      }
      else {
        // From cookies
        if (isset($_COOKIE[$name])) {
          return $_COOKIE[$name];
        }
        else {
          return NULL;
        }
      }
    }
    return NULL;
  }

  /**
   * Clean 'cleantalk_sessions' table
   */
  private static function _apbct_alt_sessions__remove_old() {
    if (rand(0, 1000) < APBCT_SESSION__CHANCE_TO_CLEAN) {
      /** @var \Cleantalk\Common\Db\Db $db_class */
      $db_class = Mloader::get('Db');
      $db_obj = $db_class::getInstance();

      $connection = \Drupal::database();
      $query = $db_obj->altCookiesClearQuery('cleantalk_sessions');
      $connection->query($query);
    }
  }

  /**
   * Get hash session ID
   *
   * @return string
   */
  private static function _apbct_alt_session__id__get() {
    $id = CleantalkHelper::ipGet()
      . filter_input(INPUT_SERVER, 'HTTP_USER_AGENT')
      . filter_input(INPUT_SERVER, 'HTTP_ACCEPT_LANGUAGE');
    return hash('sha256', $id);
  }

  /**
   * Cookie test
   *
   * @return int   1|0
   */
  private static function _cleantalk_apbct_cookies_test() {
    if (\Drupal::config('cleantalk.settings')->get('cleantalk_set_cookies')) {
      if (\Drupal::config('cleantalk.settings')->get(
        'cleantalk_alternative_cookies_session'
      )) {
        return 1;
      }

      $apbct_get_cookie_result = self::apbct_getcookie('apbct_cookies_test');

      if (is_null($apbct_get_cookie_result)) {
          return NULL;
      }

      $cookie_test = json_decode(
        urldecode($apbct_get_cookie_result),
        TRUE
      );

      if (is_null($cookie_test)) {
        return 0;
      }

      $check_string = trim(
        \Drupal::config('cleantalk.settings')->get('cleantalk_authkey') ?: ''
      );

      foreach ($cookie_test['cookies_names'] as $cookie_name) {
        $cookie_value = self::apbct_getcookie($cookie_name);
        if (is_null($cookie_value)) {
          $check_string .= '';
          continue;
        }
        $check_string .= urldecode($cookie_value);
      }
      unset($cookie_name);

      if ($cookie_test['check_value'] == md5($check_string)) {
        return 1;
      }
      else {
        return 0;
      }
    }
    return NULL;
  }

  /**
   * Cleantalk inner function - show error message and exit.
   */

  public static function _cleantalk_die($message) {
    $output = '<!DOCTYPE html><!-- Ticket #11289, IE bug fix: always pad the error page with enough characters such that it is greater than 512 bytes, even after gzip compression abcdefghijklmnopqrstuvwxyz1234567890aabbccddeeffgghhiijjkkllmmnnooppqqrrssttuuvvwwxxyyzz11223344556677889900abacbcbdcdcededfefegfgfhghgihihjijikjkjlklkmlmlnmnmononpopoqpqprqrqsrsrtstsubcbcdcdedefefgfabcadefbghicjkldmnoepqrfstugvwxhyz1i234j567k890laabmbccnddeoeffpgghqhiirjjksklltmmnunoovppqwqrrxsstytuuzvvw0wxx1yyz2z113223434455666777889890091abc2def3ghi4jkl5mno6pqr7stu8vwx9yz11aab2bcc3dd4ee5ff6gg7hh8ii9j0jk1kl2lmm3nnoo4p5pq6qrr7ss8tt9uuvv0wwx1x2yyzz13aba4cbcb5dcdc6dedfef8egf9gfh0ghg1ihi2hji3jik4jkj5lkl6kml7mln8mnm9ono--><html xmlns="http://www.w3.org/1999/xhtml" lang="en-US"><head>    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />    <title>Blacklisted</title>    <style type="text/css">        html {            background: #f1f1f1;        }        body {            background: #fff;            color: #444;            font-family: "Open Sans", sans-serif;            margin: 2em auto;            padding: 1em 2em;            max-width: 700px;            -webkit-box-shadow: 0 1px 3px rgba(0,0,0,0.13);            box-shadow: 0 1px 3px rgba(0,0,0,0.13);        }        h1 {            border-bottom: 1px solid #dadada;            clear: both;            color: #666;            font: 24px "Open Sans", sans-serif;            margin: 30px 0 0 0;            padding: 0;            padding-bottom: 7px;        }        #error-page {            margin-top: 50px;        }        #error-page p {            font-size: 14px;            line-height: 1.5;            margin: 25px 0 20px;        }        a {            color: #21759B;            text-decoration: none;        }        a:hover {            color: #D54E21;        }            </style></head><body id="error-page">    <p><center><b style="color: #49C73B;">Clean</b><b style="color: #349ebf;">Talk.</b> Spam protection</center><br><br>' . $message . '<script>setTimeout("history.back()", 5000);</script></p><p><a href="javascript:history.back()">&laquo; Back</a></p></body></html>';
    die($output);
  }

  /**
   * Cleantalk inner function - gets JavaScript checking value.
   */

  public static function _cleantalk_get_checkjs_value() {
    return md5(
      \Drupal::config('cleantalk.settings')->get(
        "cleantalk_authkey"
      ) . '+' . \Drupal::config('system.site')->get("mail")
    );
  }

  /**
   * Cleantalk inner function - performs antispam checking.
   */

  public static function _cleantalk_check_spam(
    $spam_check,
    $form_errors = NULL
  ) {
    global $cleantalk_executed;

    $curr_user = \Drupal::currentUser();

    // Exclusion. Administrator.
    if ($curr_user->hasPermission(
        'administer modules'
      ) || $cleantalk_executed) {
      return NULL;
    }

    $ct_authkey = \Drupal::config('cleantalk.settings')->get(
      'cleantalk_authkey'
    );
    if (!$ct_authkey) {
      return NULL;
    }

    // Exclusion. By roles.
    $roles = \Drupal::config('cleantalk.settings')->get(
      'cleantalk_roles_exclusions'
    );

    if (!empty($roles)) {
      foreach ($roles as $role_id) {
        if (self::_cleantalk_user_has_role_id($role_id, $curr_user)) {
          return NULL;
        }
      }
    }

    // Exclusion. By number of posted comments
    if ($curr_user->id()) {
      $user = \Drupal\user\Entity\User::load($curr_user->id());
      $uid = $user
        ->get('uid')
        ->value;

      // Don't check reged user with >= 'cleantalk_check_comments_min_approved' approved msgs.
      if (is_object($user) && $user->get('uid')->value > 0 && \Drupal::service(
          'module_handler'
        )->moduleExists('comment')) {
        $result = \Drupal::database()
          ->query(
            'SELECT count(*) AS count FROM {comment_field_data} WHERE uid=:uid AND status=1',
            [':uid' => $uid]
          )
          ->fetchObject()
          ->count;
        $count = intval($result);
        $ct_comments = \Drupal::config('cleantalk.settings')
          ->get('cleantalk_check_comments_min_approved');
        if ($count >= $ct_comments) {
          return NULL;
        }
      }
    }

    // Exclusion. By URLs
    $url_exclusion = explode(
      ",",
      \Drupal::config('cleantalk.settings')->get(
        'cleantalk_url_exclusions'
      )
    );
    if (is_array($url_exclusion) && count($url_exclusion)) {
      $check_type = \Drupal::config('cleantalk.settings')
        ->get('cleantalk_url_regexp');

      foreach ($url_exclusion as $key => $value) {
        if (!empty($value)) {
          if ($check_type == 1) { // If RegExp
            if (@preg_match(
              '#' . trim($value) . '#',
              $_SERVER['REQUEST_URI']
            )) {
              return NULL;
            }
          }
          else {
            if (strpos(
                $_SERVER['REQUEST_URI'],
                $value
              ) !== FALSE) { // Simple string checking
              return NULL;
            }
          }
          if (strpos(trim($value), 'node') !== FALSE && strpos(
              $_SERVER['REQUEST_URI'],
              'q=comment/reply/'
            ) !== FALSE) {
            $get_node = array_values(
              array_slice(explode('/', trim($value)), -1)
            )[0];
            $current_reply_id = array_values(
              array_slice(explode('/', $_SERVER['REQUEST_URI']), -1)
            )[0];

            if ($get_node == $current_reply_id) {
              return NULL;
            }
          }
        }
      }
    }

    $ct_ws = self::_cleantalk_get_ws();

    if (!self::apbct_getcookie('ct_check_js')) {
      $checkjs = NULL;
    }

    elseif (self::apbct_getcookie(
        'ct_check_js'
      ) == self::_cleantalk_get_checkjs_value()) {
      $checkjs = 1;
    }

    else {
      $checkjs = 0;
    }

    $ct = new Cleantalk();
    $ct->work_url = $ct_ws['work_url'];
    $ct->server_url = $ct_ws['server_url'];
    $ct->server_ttl = $ct_ws['server_ttl'];
    $ct->server_changed = $ct_ws['server_changed'];
    $role_exclusions = \Drupal::config('cleantalk.settings')->get(
      'cleantalk_roles_exclusions'
    );
    $ct_options = [
      'access_key' => $ct_authkey,
      'cleantalk_check_comments' => \Drupal::config('cleantalk.settings')->get(
        'cleantalk_check_comments'
      ),
      'cleantalk_check_comments_automod' => \Drupal::config(
        'cleantalk.settings'
      )->get('cleantalk_check_comments_automod'),
      'cleantalk_check_comments_min_approved' => \Drupal::config(
        'cleantalk.settings'
      )->get('cleantalk_check_comments_min_approved'),
      'cleantalk_check_register' => \Drupal::config('cleantalk.settings')->get(
        'cleantalk_check_register'
      ),
      'cleantalk_check_webforms' => \Drupal::config('cleantalk.settings')->get(
        'cleantalk_check_webforms'
      ),
      'cleantalk_check_contact_forms' => \Drupal::config('cleantalk.settings')
        ->get('cleantalk_check_contact_forms'),
      'cleantalk_check_forum_topics' => \Drupal::config('cleantalk.settings')
        ->get('cleantalk_check_forum_topics'),
      'cleantalk_check_search_form' => \Drupal::config('cleantalk.settings')
        ->get('cleantalk_check_search_form'),
      'cleantalk_url_exclusions' => \Drupal::config('cleantalk.settings')->get(
        'cleantalk_url_exclusions'
      ),
      'cleantalk_url_regexp' => \Drupal::config('cleantalk.settings')->get(
        'cleantalk_url_regexp'
      ),
      'cleantalk_fields_regexp' => \Drupal::config('cleantalk.settings')->get(
        'cleantalk_fields_regexp'
      ),
      'cleantalk_fields_exclusions' => \Drupal::config('cleantalk.settings')
        ->get('cleantalk_fields_exclusions'),
      'cleantalk_roles_exclusions' => !empty($role_exclusions) ? implode(
        ',',
        $role_exclusions
      ) : '',
      'cleantalk_add_search_noindex' => \Drupal::config('cleantalk.settings')
        ->get('cleantalk_add_search_noindex'),
      'cleantalk_search_noindex' => \Drupal::config('cleantalk.settings')->get(
        'cleantalk_search_noindex'
      ),
      'cleantalk_set_cookies' => \Drupal::config('cleantalk.settings')->get(
        'cleantalk_set_cookies'
      ),
      'cleantalk_alternative_cookies_session' => \Drupal::config(
        'cleantalk.settings'
      )->get('cleantalk_alternative_cookies_session'),
      'cleantalk_check_added_content' => \Drupal::config('cleantalk.settings')
        ->get('cleantalk_check_added_content'),
      'cleantalk_check_ccf' => \Drupal::config('cleantalk.settings')->get(
        'cleantalk_check_ccf'
      ),
      'cleantalk_check_external' => \Drupal::config('cleantalk.settings')->get(
        'cleantalk_check_external'
      ),
      'cleantalk_link' => \Drupal::config('cleantalk.settings')->get(
        'cleantalk_link'
      ),
      'cleantalk_bot_detector' => \Drupal::config('cleantalk.settings')->get(
        'cleantalk_bot_detector'
      ),
      'cleantalk_sfw' => \Drupal::config('cleantalk.settings')->get(
        'cleantalk_sfw'
      ),
    ];

    $sender_info = \Drupal\Component\Serialization\Json::encode(
    // We have to use $_SERVER and $_COOKIE arrays instead \Drupal::request() for earlier access to this data from BootSubscriber
      [
        'cms_lang' => \Drupal::languageManager()->getCurrentLanguage()->getId(),
        'REFFERRER' => isset($_SERVER['HTTP_REFERER']) ? htmlspecialchars(
          $_SERVER['HTTP_REFERER']
        ) : NULL,
        'page_url' => isset($_SERVER['SERVER_NAME'], $_SERVER['REQUEST_URI']) ? htmlspecialchars(
          $_SERVER['SERVER_NAME'] . $_SERVER['REQUEST_URI']
        ) : NULL,
        'USER_AGENT' => isset($_SERVER['HTTP_USER_AGENT']) ? htmlspecialchars(
          $_SERVER['HTTP_USER_AGENT']
        ) : NULL,
        'ct_options' => \Drupal\Component\Serialization\Json::encode(
          $ct_options
        ),
        'REFFERRER_PREVIOUS' => self::apbct_getcookie('apbct_prev_referer'),
        'cookies_enabled' => self::_cleantalk_apbct_cookies_test(),
        'fields_number' => count($spam_check),
        'js_timezone' => self::apbct_getcookie('ct_timezone'),
        'mouse_cursor_positions' => !empty($_COOKIE['ct_pointer_data']) ? json_decode(
          stripslashes($_COOKIE['ct_pointer_data']),
          TRUE
        ) : NULL,
        'key_press_timestamp' => !empty($_COOKIE['ct_fkp_timestamp']) ? $_COOKIE['ct_fkp_timestamp'] : NULL,
        'page_set_timestamp' => !empty($_COOKIE['ct_ps_timestamp']) ? $_COOKIE['ct_ps_timestamp'] : NULL,
        'form_validation' => ($form_errors && is_array(
            $form_errors
          )) ? json_encode(
          [
            'validation_notice' => strip_tags(json_encode($form_errors)),
            'page_url' => $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'],
          ]
        ) : NULL,
        'has_scrolled' => self::apbct_getcookie(
          'ct_has_scrolled'
        ) ? json_encode(self::apbct_getcookie('ct_has_scrolled')) : NULL,
      ]
    );
    if ($spam_check['type'] == 'custom_contact_form' && isset($_SERVER['HTTP_REFERER']) && htmlspecialchars(
        $_SERVER['HTTP_REFERER']
      ) === 'https://www.google.com/') {
      $spam_check['type'] = 'site_search_drupal9';
    }
    $post_info = \Drupal\Component\Serialization\Json::encode(
      [
        'comment_type' => $spam_check['type'],
        'post_url' => isset($_SERVER['HTTP_REFERER']) ? htmlspecialchars(
          $_SERVER['HTTP_REFERER']
        ) : NULL,
      ]
    );
    $ct_request = new CleantalkRequest();
    $ct_request->auth_key = $ct_authkey;
    $ct_request->agent = CLEANTALK_USER_AGENT;
    $ct_request->response_lang = 'en';
    $ct_request->js_on = $checkjs;
    $ct_request->sender_info = $sender_info;
    $ct_request->post_info = $post_info;
    $ct_request->sender_email = $spam_check['sender_email'];
    $ct_request->sender_nickname = $spam_check['sender_nickname'];
    $ct_request->sender_ip = CleantalkHelper::ipGet('real', FALSE);
    $ct_request->x_forwarded_for = CleantalkHelper::ipGet(
      'x_forwarded_for',
      FALSE
    );
    $ct_request->x_real_ip = CleantalkHelper::ipGet('x_real_ip', FALSE);
    $ct_request->submit_time = isset($spam_check['multistep_submit_time']) ? self::_cleantalk_get_submit_time(
      $spam_check['multistep_submit_time']
    ) : self::_cleantalk_get_submit_time(
      self::apbct_getcookie('apbct_timestamp')
    );
    $ct_request->event_token = self::getEventToken();

    switch ($spam_check['type']) {
      case 'comment':

      case 'contact':

      case 'added_content':

      case 'forum_topic':

      case 'webform':

      case 'site_search_drupal9':

      case 'custom_contact_form':

      case 'external_form':

        $timelabels_key = 'mail_error_comment';
        if (is_array($spam_check['message_body'])) {
          $spam_check['message_body'] = isset($spam_check['message_body']['message']) ? $spam_check['message_body']['message'] : implode(
            "\n\n",
            $spam_check['message_body']
          );
        }

        $ct_request->message = $spam_check['message_title'] . " \n\n" . strip_tags(
            $spam_check['message_body']
          );
        $ct_result = $ct->isAllowMessage($ct_request);

        break;

      case 'register':

        $timelabels_key = 'mail_error_reg';
        $ct_request->tz = $spam_check['timezone'];
        $ct_result = $ct->isAllowUser($ct_request);

        break;
    }

    $cleantalk_executed = TRUE;
    $ret_val = [];
    $ret_val['ct_request_id'] = $ct_result->id;

    if ($ct->server_change) {
      self::_cleantalk_set_ws($ct->work_url, $ct->server_ttl, time());
    }

    // First check errstr flag.

    if (!empty($ct_result->errstr) || (!empty($ct_result->inactive) && $ct_result->inactive == 1)) {
      // Cleantalk error so we go default way (no action at all).

      $ret_val['errno'] = 1;

      if ($checkjs == 0) {
        $ret_val['allow'] = 0;
      }

      // Just inform admin.

      $err_title = $_SERVER['SERVER_NAME'] . ' - CleanTalk hook error';

      if (!empty($ct_result->errstr)) {
        $ret_val['errstr'] = self::_cleantalk_filter_response(
          $ct_result->errstr
        );
      }

      else {
        $ret_val['errstr'] = self::_cleantalk_filter_response(
          $ct_result->comment
        );
      }

      $send_flag = FALSE;

      $result = \Drupal::database()
        ->select('cleantalk_timelabels', 'c')
        ->fields('c', ['ct_value'])
        ->condition('ct_key', $timelabels_key, '=')
        ->execute();
      $results = $result->fetchCol(0);

      if (count($results) == 0) {
        $send_flag = TRUE;
      }

      elseif ($result->fetchObject() && \Drupal::time()->getRequestTime(
        ) - 900 > $result->fetchObject()->ct_value) {
        // 15 minutes.

        $send_flag = TRUE;
      }

      if ($send_flag) {
        \Drupal::database()->merge('cleantalk_timelabels')->key(
          ['ct_key' => $timelabels_key,]
        )->fields(['ct_value' => \Drupal::time()->getRequestTime(),])->execute(
        );

        $to_mail = \Drupal::state()->get('site_mail');

        if (!empty($to_mail)) {
          drupal_mail(
            "cleantalk",
            $timelabels_key,
            $to_mail,
            language_default(),
            [
              'subject' => $err_title,
              'body' => $ret_val['errstr'],
              'headers' => [],
            ],
            $to_mail,
            TRUE
          );
        }
      }

      return $ret_val;
    }

    $ret_val['errno'] = 0;

    if ($ct_result->allow == 1) {
      // Not spammer.

      $ret_val['allow'] = 1;

      // Store request_id in globals to store it in DB later.

      self::_cleantalk_ct_result('set', $ret_val['allow'], $ct_result->id);
      // Don't store 'ct_result_comment', means good comment.
    }

    else {
      // Spammer.

      $ret_val['allow'] = 0;
      $ret_val['ct_result_comment'] = self::_cleantalk_filter_response(
        $ct_result->comment
      );

      // Check stop_queue flag.

      if ($spam_check['type'] == 'comment') {
        // Spammer and stop_queue == 0 - to manual approvement.

        $ret_val['stop_queue'] = $ct_result->stop_queue;

        // Store request_id and comment in static to store them in DB later.

        self::_cleantalk_ct_result(
          'set',
          $ct_result->id,
          $ret_val['allow'],
          $ret_val['ct_result_comment']
        );
      }
    }

    return $ret_val;
  }

  /**
   * Cleantalk inner function - performs CleanTalk comment|errstr filtering.
   */

  public static function _cleantalk_filter_response($ct_response) {
    if (preg_match('//u', $ct_response)) {
      $err_str = preg_replace('/\*\*\*/iu', '', $ct_response);
    }

    else {
      $err_str = preg_replace('/\*\*\*/i', '', $ct_response);
    }

    return \Drupal\Component\Utility\Xss::filter($err_str, ['a']);
  }

  /**
   * Cleantalk inner function - stores spam checking result.
   */

  public static function _cleantalk_ct_result(
    $cmd = 'get',
    $id = '',
    $allow = 1,
    $comment = ''
  ) {
    static $request_id = '';
    static $result_allow = 1;
    static $result_comment = '';

    if ($cmd == 'set') {
      $request_id = $id;
      $result_allow = $allow;
      $result_comment = $comment;
    }

    else {
      return [
        'ct_request_id' => $request_id,
        'ct_result_allow' => $result_allow,
        'ct_result_comment' => $result_comment,
      ];
    }
  }

  /**
   * Cleantalk inner function - gets working server.
   */

  public static function _cleantalk_get_ws() {
    return [
      'work_url' => \Drupal::state()->get('cleantalk_work_url'),
      'server_url' => CLEANTALK_MODERATE_URL,
      'server_ttl' => \Drupal::state()->get('cleantalk_server_ttl'),
      'server_changed' => \Drupal::state()->get('cleantalk_server_changed'),
    ];
  }

  /**
   * Cleantalk inner function - sets working server.
   */

  public static function _cleantalk_set_ws(
    $work_url = CLEANTALK_MODERATE_URL,
    $server_ttl = 0,
    $server_changed = 0
  ) {
    \Drupal::state()->set('cleantalk_work_url', $work_url);
    \Drupal::state()->set('cleantalk_server_ttl', $server_ttl);
    \Drupal::state()->set('cleantalk_server_changed', $server_changed);
  }

  /**
   * Cleantalk inner function - check form handlers for save to prevent
   * checking drafts/preview.
   */

  public static function _cleantalk_check_form_submit_handlers($submitHandlers
  ) {
    if ($submitHandlers && is_array($submitHandlers)) {
      foreach ($submitHandlers as $handler) {
        if ($handler === '::save') {
          return TRUE;
        }
      }
    }

    return FALSE;
  }

  public static function apbct_sfw_update($access_key = '') {

    if (empty($access_key)) {
      $access_key = trim(
        \Drupal::config('cleantalk.settings')->get('cleantalk_authkey') ?: ''
      );
      if (empty($access_key)) {
        return false;
      }
    }
    $firewall = new Firewall(
      $access_key,
      APBCT_TBL_FIREWALL_LOG
    );

    $fw_updater = $firewall->getUpdater();
    $fw_updater->update();
    return true;
  }

  public static function apbct_sfw_send_logs($access_key = '') {
    if (empty($access_key)) {
      $access_key = trim(
        \Drupal::config('cleantalk.settings')->get('cleantalk_authkey') ?: ''
      );
      if (empty($access_key)) {
        return FALSE;
      }
    }

    $firewall = new Firewall($access_key, APBCT_TBL_FIREWALL_LOG);
    $result = $firewall->sendLogs();

    return TRUE;
  }

  /**
   * Triggered by cron
   */
  public static function apbct_sfw_ac__clear_table() {
    if (\Drupal::config('cleantalk.settings')->get('cleantalk_sfw_ac')
      || \Drupal::config('cleantalk.settings')->get('cleantalk_sfw_antiflood')
    ) {
      $anti_flood = new \Cleantalk\Custom\Firewall\Modules\AntiFlood(
        APBCT_TBL_FIREWALL_LOG,
        [
          'chance_to_clean' => 100,
          'db__table__ac_logs' => APBCT_TBL_AC_LOGS
        ]
      );
      $anti_flood->clearTable();
      unset($anti_flood);
    }
  }

  public static function _cleantalk_user_has_role_id($role_id, $user = NULL) {
    $roles = \Drupal::currentUser()->getRoles();

    if (is_array($roles) && in_array($role_id, $roles)) {
      return TRUE;
    }

    return FALSE;
  }

  public static function cleantalk_get_user_roles() {
    $roles = \Drupal\user\Entity\Role::loadMultiple();
    $roles_arr = [];
    foreach ($roles as $role) {
      $roles_arr[$role->get('id')] = $role->get('label');
    }
    asort($roles_arr);
    return $roles_arr;
  }

  public static function cleantalk_get_user_roles_default() {
    if (empty(
    \Drupal::config('cleantalk.settings')->get(
      'cleantalk_roles_exclusions'
    )
    )) {
      $roles = self::cleantalk_get_user_roles();

      foreach ($roles as $role_id => $role_name) {
        if (strpos('administrator', $role_id) === FALSE) {
          unset($roles[$role_id]);
        }
      }
      return array_keys($roles);
    }
    else {
      $roles = \Drupal::config('cleantalk.settings')->get(
        'cleantalk_roles_exclusions'
      );
      $config_roles = [];
      foreach ((array) $roles as $role => $role_name) {
        $config_roles[$role_name] = $role_name;
      }
      return $config_roles;
    }
  }

  public static function print_form($arr, $k) {
    // Fix for pages04.net forms
    if (isset($arr['formSourceName'])) {
      $tmp = [];
      foreach ($arr as $key => $val) {
        $tmp_key = str_replace('_', '+', $key);
        $tmp[$tmp_key] = $val;
      }
      $arr = $tmp;
      unset($tmp, $key, $tmp_key, $val);
    }

    foreach ($arr as $key => $value) {
      if (!is_array($value)) {
        print '<textarea
				name="' . ($k == '' ? $key : $k . '[' . $key . ']') . '"
				style="display:none;">' . htmlspecialchars($value)
          . '</textarea>';
      }
      else {
        self::print_form($value, $k == '' ? $key : $k . '[' . $key . ']');
      }
    }
  }

  public static function ct_die($comment) {
    $err_text = '<center>' . ((defined(
          'CLEANTALK_DISABLE_BLOCKING_TITLE'
        ) && CLEANTALK_DISABLE_BLOCKING_TITLE == TRUE) ? '' : '<b style="color: #49C73B;">Clean</b><b style="color: #349ebf;">Talk.</b> ') . 'Spam protection' . "</center><br><br>\n<center>" . $comment . "</center>";
    $err_text .= '<script>setTimeout("history.back()", 5000);</script>';
    die($err_text);
  }

  /**
   * AntiCrawler cookie value
   *
   * @return false|string
   */
  public static function create_ac_cookie_value() {
    return hash(
      'sha256',
      \Drupal::config('cleantalk.settings')->get(
        "cleantalk_authkey"
      ) . \Drupal::config('cleantalk.settings')->get("cleantalk_salt")
    );
  }

  public static function apbct_process_buffer($content, $path_info) {
    if (!\Drupal::service('router.admin_context')->isAdminRoute()
      && !empty($content)
      && \Drupal::config('cleantalk.settings')->get('cleantalk_check_external')
      && \Drupal::config('cleantalk.settings')->get(
        'cleantalk_check_external__capture_buffer'
      )
    ) {
      if (TRUE) {
        // Modify it by DOM
        $output = CleantalkFuncs::apbct_buffer_modify_by_dom(
          $content,
          $path_info
        );
      }
      else {
        // Modify it by string
        $output = CleantalkFuncs::apbct_buffer_modify_by_string(
          $content,
          $path_info
        );
      }
      return $output;
    }
    return $content;
  }

  private static function apbct_buffer_modify_by_dom($content, $path_info) {
    $site_url = CleantalkHelper::getSiteUrl();
    $site__host = parse_url($site_url, PHP_URL_HOST);

    $dom = new \DOMDocument();
    @$dom->loadHTML($content, LIBXML_HTML_NOIMPLIED | LIBXML_HTML_NODEFDTD);

    $forms = $dom->getElementsByTagName('form');

    foreach ($forms as $form) {
      $action = $form->getAttribute('action');
      $action = $action ?: $site_url;
      $action__host = parse_url($action, PHP_URL_HOST);

      // Check if the form directed to the third party site
      if ($action__host && $site__host != $action__host) {
        $method = $form->getAttribute('method');
        $method = $method ?: 'get';
        // Directs form to our site
        $form->setAttribute('method', 'POST');
        $form->setAttribute('action', $site_url . $path_info);

        // Add cleantalk_hidden_action
        $new_input = $dom->createElement('input');
        $new_input->setAttribute('type', 'hidden');
        $new_input->setAttribute('name', 'cleantalk_hidden_action');
        $new_input->setAttribute('value', $action);
        $form->appendChild($new_input);

        // Add cleantalk_hidden_method
        $new_input = $dom->createElement('input');
        $new_input->setAttribute('type', 'hidden');
        $new_input->setAttribute('name', 'cleantalk_hidden_method');
        $new_input->setAttribute('value', $method);
        $form->appendChild($new_input);
      }
    }
    unset($form);

    $html = $dom->getElementsByTagName('html');

    return is_object(
      $html
    ) && isset($html[0], $html[0]->childNodes[0]) && $dom->getElementsByTagName(
      'rss'
    )->length == 0
      ? $dom->saveHTML()
      : $content;
  }

  private static function apbct_buffer_modify_by_string($content, $path_info) {
    $site_url = CleantalkHelper::getSiteUrl();
    $site__host = parse_url($site_url, PHP_URL_HOST);

    preg_match_all(
      '/<form\s*.*>\s*.*<\/form>/',
      $content,
      $matches,
      PREG_SET_ORDER
    );

    if (count($matches) > 0) {
      foreach ($matches as $match) {
        preg_match('/action="(\S*)"/', $match[0], $group_action);
        $action = count($group_action) > 0 ? $group_action[1] : $site_url;

        $action__host = parse_url($action, PHP_URL_HOST);
        if ($site__host != $action__host) {
          preg_match('/method="(\S*)"/', $match[0], $group_method);
          $method = count($group_method) > 0 ? $group_method[1] : 'get';

          $hidden_fields = '<input type="hidden" name="cleantalk_hidden_action" value="' . $action . '">';
          $hidden_fields .= '<input type="hidden" name="cleantalk_hidden_method" value="' . $method . '">';

          $modified_match = preg_replace(
            '/action="\S*"/',
            'action="' . $site_url . $path_info . '"',
            $match[0]
          );
          $modified_match = preg_replace(
            '/method="\S*"/',
            'method="POST"',
            $modified_match
          );
          $modified_match = str_replace(
            '</form>',
            $hidden_fields . '</form>',
            $modified_match
          );
          $content = str_replace($match[0], $modified_match, $content);
        }
      }
    }

    return $content;
  }

  /**
   * Filter validate actions
   *
   * Sort and remove unnecessary actions
   */
  public static function filter_validate_actions($validate_actions) {
    $priority_of_actions = [
      'cleantalk_validate_webform',
      'cleantalk_validate_contact_message',
    ];

    usort(
      $validate_actions, function ($a, $b) use ($priority_of_actions) {
      $keyA = array_search($a, $priority_of_actions);
      $keyB = array_search($b, $priority_of_actions);

      if ($keyA == $keyB) {
        return 0;
      }

      return ($keyA < $keyB) ? -1 : 1;
    }
    );

    $favorite_action = '';

    foreach ($validate_actions as $value) {
      if (in_array($value, $priority_of_actions)) {
        $favorite_action = $value;
        break;
      }
    }

    if ($favorite_action) {
      foreach ($validate_actions as $key => $value) {
        if (in_array(
            $value,
            $priority_of_actions
          ) && $value !== $favorite_action) {
          unset($validate_actions[$key]);
        }
      }
    }

    return $validate_actions;
  }

  /**
   * Get event token. Check POST field by defaults. If no data provided, try to get token form alt sessions if enabled.
   * @return string|null Null if no token found, token otherwise.
   */
  private static function getEventToken()
  {
    $event_token = Post::get('ct_bot_detector_event_token');

    if ( empty($event_token) && \Drupal::config('cleantalk.settings')->get('cleantalk_alternative_cookies_session')) {
      $event_token = self::apbct_getcookie('apbct_event_token');
    }

    return !empty($event_token) && is_string($event_token)
      ? htmlspecialchars($event_token)
      : null;
  }
}
