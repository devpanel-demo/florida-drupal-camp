<?php

namespace Drupal\cleantalk\EventSubscriber;

// Autoload.
require_once( __DIR__ . '/../../lib/autoload.php');

use Cleantalk\Custom\StorageHandler\StorageHandler;
use Cleantalk\Custom\Updater\Updater;
use Drupal\Core\Language\LanguageInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\HttpKernelInterface;

// CleanTalk classes.
use Cleantalk\Common\Mloader\Mloader;
use Cleantalk\Common\Variables\Server;
use Cleantalk\Common\Firewall\Firewall;
use Cleantalk\Common\Firewall\Modules\Sfw as SFW;
use Cleantalk\Custom\Firewall\Modules\AntiCrawler;
use Cleantalk\Custom\Firewall\Modules\AntiFlood;

if (! defined('CLEANTALK_USER_AGENT') ) {
  define('CLEANTALK_USER_AGENT', 'drupal-' . \Drupal\cleantalk\CleantalkFuncs::$version);
}

if (! defined('CLEANTALK_MODERATE_URL') ) {
  define('CLEANTALK_MODERATE_URL', 'https://moderate.cleantalk.org');
}

if (!defined('APBCT_TBL_FIREWALL_DATA')) {
  define('APBCT_TBL_FIREWALL_DATA', 'cleantalk_sfw');
  // Table with firewall data.
}
if (!defined('APBCT_TBL_FIREWALL_LOG')) {
  define('APBCT_TBL_FIREWALL_LOG', 'cleantalk_sfw_logs');
  // Table with firewall logs.
}
if (!defined('APBCT_TBL_AC_LOGS')) {
  define('APBCT_TBL_AC_LOGS', 'cleantalk_ac_logs');
  // Table with firewall logs.
}
if (!defined('APBCT_TBL_AC_UA_BL')) {
  define('APBCT_TBL_AC_UA_BL', 'cleantalk_ua_bl');
  // Table with User-Agents blacklist.
}
if (!defined('APBCT_TBL_SESSIONS')) {
  define('APBCT_TBL_SESSIONS', 'cleantalk_sessions');
  // Table with session data.
}
if (!defined('APBCT_SPAMSCAN_LOGS')) {
  define('APBCT_SPAMSCAN_LOGS', 'cleantalk_spamscan_logs');
  // Table with session data.
}
if (!defined('APBCT_SELECT_LIMIT')) {
  define('APBCT_SELECT_LIMIT', 5000);
  // Select limit for logs.
}
if (!defined('APBCT_WRITE_LIMIT')) {
  define('APBCT_WRITE_LIMIT', 5000);
  // Write limit for firewall data.
}

if (!defined('APBCT_DIR_PATH')) {
  define('APBCT_DIR_PATH', dirname(dirname(__DIR__)));
  // Write limit for firewall data.
}

// Cron handlers specific names
if (!defined('APBCT_CRON_HANDLER__SFW_UPDATE')) {
  define('APBCT_CRON_HANDLER__SFW_UPDATE', '\Drupal\cleantalk\CleantalkFuncs::apbct_sfw_update');
}
if (!defined('APBCT_CRON_HANDLER__SFW_LOGS')) {
  define('APBCT_CRON_HANDLER__SFW_LOGS', '\Drupal\cleantalk\CleantalkFuncs::apbct_sfw_send_logs');
}
if (!defined('APBCT_CRON_HANDLER__AC_CLEAR_TABLE')) {
  define('APBCT_CRON_HANDLER__AC_CLEAR_TABLE', '\Drupal\cleantalk\CleantalkFuncs::apbct_sfw_ac__clear_table');
}

/**
 * Boot Subscriber.
 */
class BootSubscriber implements HttpKernelInterface
{
  /**
   * The wrapped HTTP kernel.
   *
   * @var \Symfony\Component\HttpKernel\HttpKernelInterface
   */

  protected $httpKernel;

  /**
   * Creates an HTTP middleware handler.
   *
   * @param \Symfony\Component\HttpKernel\HttpKernelInterface $kernel The HTTP kernel.
   */
  public function __construct(HttpKernelInterface $kernel) {
    $this->httpKernel = $kernel;
  }

  /**
   * {@inheritdoc}
   */
  public function handle(Request $request, $type = self::MAIN_REQUEST, $catch = TRUE) : Response {

    Updater::updateActions();

    if (strpos($request->server->get('REQUEST_URI'), '/admin/') === FALSE) {
      // SpamFireWall start
      if (\Drupal::config('cleantalk.settings')->get('cleantalk_sfw')) {
        $cleantalk_key = trim(\Drupal::config('cleantalk.settings')->get('cleantalk_authkey'));

        StorageHandler::$jsLocation = $request->getSchemeAndHttpHost() .
        \Drupal::service('extension.list.module')->getPath('cleantalk') .
        "/js/apbct-functions.js";

        if ($cleantalk_key) {
          $current_language = \Drupal::languageManager()->getCurrentLanguage(LanguageInterface::TYPE_CONTENT);
          $locale_code = $current_language->getId();

            try {
                $firewall = new Firewall(
                    $cleantalk_key,
                    APBCT_TBL_FIREWALL_LOG,
                  $locale_code
                );

              $fw_stats = Firewall::getFwStats();
              if (empty($fw_stats->updating_folder)) {
                $fw_stats->updating_folder = StorageHandler::getUpdatingFolder();
                Firewall::saveFwStats($fw_stats);
              }

                $firewall->loadFwModule(new SFW(
                        APBCT_TBL_FIREWALL_LOG,
                        APBCT_TBL_FIREWALL_DATA
                    )
                );

                /**
                 * Anti-crawler module start
                 */
                if (
                    \Drupal::config('cleantalk.settings')->get('cleantalk_sfw_ac') &&
                    \Drupal::config('cleantalk.settings')->get('cleantalk_set_cookies')
                ) {
                    $firewall->loadFwModule(new AntiCrawler(
                            APBCT_TBL_AC_UA_BL,
                            array(
                                'db__table__ac_logs' => APBCT_TBL_AC_LOGS,
                                'db__table__sfw_logs' => APBCT_TBL_FIREWALL_LOG,
                                'db__table__sfw' => APBCT_TBL_FIREWALL_DATA,
                            )
                        )
                    );
                }

                /**
                 * Anti-flood module start
                 */
                if ( \Drupal::config('cleantalk.settings')->get('cleantalk_sfw_antiflood') ) {
                    $firewall->loadFwModule(new AntiFlood(
                        APBCT_TBL_FIREWALL_LOG,
                        array(
                            'view_limit' => \Drupal::config('cleantalk.settings')->get('cleantalk_sfw_antiflood_limit'),
                            'db__table__ac_logs' => APBCT_TBL_AC_LOGS,
                            'db__table__sfw' => APBCT_TBL_FIREWALL_DATA,
                        )
                    ));
                }

                $firewall->run();
            } catch (\Exception $e) {
                error_log('CleanTalk Firewall is not loaded: ' . $e->getMessage());
            }
        }
      }

      // Remote calls
      /** @var \Cleantalk\Common\RemoteCalls\RemoteCalls $rc_class */
      $rc_class = Mloader::get('RemoteCalls');
      // Cron
      /** @var \Cleantalk\Common\Cron\Cron $cron_class */
      $cron_class = Mloader::get('Cron');
      $cron = new $cron_class();
      $cron_option = \Drupal::state()->get($cron->getCronOptionName());
      if (empty($cron_option)) {
        $cron->saveTasks($cron->getDefaultTasks());
      }
      $tasks_to_run = $cron->checkTasks(); // Check for current tasks. Drop tasks inner counters.

      if (
        ! empty( $tasks_to_run ) && // There is tasks to run
        ! $rc_class::check() && // Do not doing CRON in remote call action
        (
          ! defined( 'DOING_CRON' ) ||
          ( defined( 'DOING_CRON' ) && DOING_CRON !== true )
        )
      ){
        $cron_res = $cron->runTasks( $tasks_to_run );
        // Handle the $cron_res for errors here.
      }
    }

    return $this->httpKernel->handle($request, $type, $catch);
  }
}
