<?php

namespace Cleantalk\Custom\Updater;

use Cleantalk\Custom\Antispam\Cleantalk;
use Cleantalk\Custom\Antispam\CleantalkRequest;
use Cleantalk\Custom\StorageHandler\StorageHandler;
use Cleantalk\Common\Mloader\Mloader;

class Updater
{
  public static function updateActions()
  {
    $storage_handler = new StorageHandler();
    $state = $storage_handler->getSetting('cleantalk_state');

    $version_from_state = $state && isset($state['version']) ? $state['version'] : '9.2.7';
    $current_version = \Drupal\cleantalk\CleantalkFuncs::$version;

    // Update logic
    if ( $version_from_state !== $current_version ) {
      // Prevent several updating running
      if ( self::isUpdatingInProgress() ) {
        return;
      }

      self::setUpdatingInProgress();

      $result = self::runUpdateActions($version_from_state, $current_version);

      //If update is successful
      if ( $result === true ) {
        self::setVersionFromPlugin($current_version);
        self::setUpdatingComplete();
      }

      // Send feedback to let cloud know about updated version.
      $ct_request = new CleantalkRequest(array(
        // General
        'auth_key' => \Drupal::config('cleantalk.settings')->get("cleantalk_authkey"),
        // Additional
        'feedback' => '0:' . CLEANTALK_USER_AGENT,
      ));
      $ct = new Cleantalk();
      $ct->server_url     = CLEANTALK_MODERATE_URL;
      $ct->sendFeedback($ct_request);
    }
  }
  /**
   * Main function to compare versions and run necessary update functions.
   *
   * @param string $current_version
   * @param string $new_version
   *
   * @return bool
   *
   * @psalm-suppress PossiblyUndefinedIntArrayOffset
   */
  private static function runUpdateActions($old_version, $new_version)
  {
    $old_version_arr = self::versionStandardization($old_version);
    $new_version_arr     = self::versionStandardization($new_version);

    $old_version_str = implode('.', $old_version_arr);
    $new_version_str     = implode('.', $new_version_arr);

    for ($ver_major = $old_version_arr[0]; $ver_major <= $new_version_arr[0]; $ver_major++) {
      for ($ver_minor = 0; $ver_minor <= 300; $ver_minor++) {
        for ($ver_fix = 0; $ver_fix <= 10; $ver_fix++) {
          if ( version_compare("{$ver_major}.{$ver_minor}.{$ver_fix}", $old_version_str, '<=') ) {
            continue;
          }

          $method_name_fix = "update_to_{$ver_major}_{$ver_minor}_{$ver_fix}";
          if ( method_exists(self::class, $method_name_fix) ) {
            $result = call_user_func([self::class, $method_name_fix]);
            if ( ! empty($result['error']) ) {
              break;
            }
          }

          $method_name_version = "update_to_{$ver_major}_{$ver_minor}";
          if ( $ver_fix == 0 && method_exists(self::class, $method_name_version) ) {
            $result = call_user_func([self::class, $method_name_version]);
            if ( ! empty($result['error']) ) {
              break;
            }
          }

          if (version_compare("{$ver_major}.{$ver_minor}.{$ver_fix}", $new_version_str, '>=')) {
            break( 2 );
          }
        }
      }
    }

    return true;
  }

  /**
   * Convert string version to an array
   *
   * @param string $version
   *
   * @return array
   */
  private static function versionStandardization($version)
  {
    $parsed_version = explode('.', $version);

    $parsed_version[0] = ! empty($parsed_version[0]) ? (int)$parsed_version[0] : 0;
    $parsed_version[1] = ! empty($parsed_version[1]) ? (int)$parsed_version[1] : 0;
    $parsed_version[2] = ! empty($parsed_version[2]) ? (int)$parsed_version[2] : 0;

    return $parsed_version;
  }

  public static function setVersionFromPlugin($version)
  {
    $storage_handler = new StorageHandler();
    $state = $storage_handler->getSetting('cleantalk_state');
    $state['version'] = $version;
    return $storage_handler->saveSetting('cleantalk_state', $state);
  }

  private static function getState()
  {
    $storage_handler = new StorageHandler();
    return $storage_handler->getSetting('cleantalk_state');
  }

  private static function saveState($state_variable_name, $state_vaiable_value)
  {
    $storage_handler = new StorageHandler();
    $state = $storage_handler->getSetting('cleantalk_state');
    $state[$state_variable_name] = $state_vaiable_value;
    return $storage_handler->saveSetting('cleantalk_state', $state);
  }

  private static function isUpdatingInProgress()
  {
    return isset(self::getState()['updating_in_progress']) && self::getState()['updating_in_progress'];
  }

  private static function setUpdatingInProgress()
  {
    self::saveState('updating_in_progress', true);
  }

  private static function setUpdatingComplete()
  {
    self::saveState('updating_in_progress', false);
  }

  public static function update_to_9_3_0()
  {
    \Drupal::service('database')->schema()->dropTable('cleantalk_sfw');
    \Drupal::service('database')->schema()->dropTable('cleantalk_sfw_logs');
    \Drupal::service('database')->schema()->dropTable('cleantalk_ac_logs');
    \Drupal::service('database')->schema()->dropTable('cleantalk_ua_bl');

    $cleantalk_sfw_table_schema = [
      'description' => 'SpamFireWall data.',
      'fields' => [
        'id' => [
          'type' => 'serial',
          'description' => "ID",
          'length' => 11,
          'not null' => TRUE,
          'unsigned' => TRUE,
        ],
        'network' => [
          'type' => 'int',
          'length' => 11,
          'unsigned' => TRUE,
          'not null' => TRUE,
          'default' => 0,
          'description' => 'Spam network.',
        ],
        'mask' => [
          'type' => 'int',
          'length' => 11,
          'unsigned' => TRUE,
          'not null' => TRUE,
          'default' => 0,
          'description' => 'Spam mask.',
        ],
        'status' => [
          'type' => 'int',
          'length' => 1,
          'unsigned' => FALSE,
          'not null' => TRUE,
          'default' => 0,
          'description' => 'Spam status.',
        ],
        'source' => [
          'type' => 'int',
          'length' => 1,
          'unsigned' => FALSE,
          'not null' => FALSE,
          'default' => NULL,
          'description' => 'Source.',
        ],
      ],
      'indexes' => [
        'network' => [
          'network',
          'mask',
        ],
      ],
      'primary key' => ['id'],
    ];

    $cleantalk_sfw_logs_table_schema = [
      'description' => 'SpamFireWall logs.',
      'fields' => [
        'id' => [
          'type' => 'varchar',
          'length' => 40,
          'not null' => TRUE,
          'description' => 'ID.',
        ],
        'ip' => [
          'type' => 'varchar',
          'length' => 15,
          'not null' => TRUE,
          'description' => 'IP.',
        ],
        'status' => [
          'type' => 'varchar',
          'length' => 50,
          'description' => 'status',
          'not null' => FALSE,
          'default' => NULL,
        ],
        'all_entries' => [
          'type' => 'int',
          'description' => 'All entries.',
        ],
        'blocked_entries' => [
          'type' => 'int',
          'description' => 'Blocked entries.',
        ],
        'entries_timestamp' => [
          'type' => 'int',
          'description' => 'time().',
        ],
        'ua_id' => [
          'type' => 'int',
          'description' => 'ua_id',
          'length' => 11,
          'not null' => FALSE,
          'default' => NULL,
          'unsigned' => TRUE,
        ],
        'ua_name' => [
          'type' => 'varchar',
          'description' => 'ua_name',
          'length' => 1024,
          'not null' => TRUE,
        ],
        'source' => [
          'type' => 'int',
          'length' => 1,
          'not null' => FALSE,
          'default' => NULL,
        ],
        'network' => [
          'type' => 'varchar',
          'length' => 20,
          'not null' => FALSE,
          'default' => NULL,
        ],
        'first_url' => [
          'type' => 'varchar',
          'length' => 100,
          'not null' => FALSE,
          'default' => NULL,
        ],
        'last_url' => [
          'type' => 'varchar',
          'length' => 100,
          'not null' => FALSE,
          'default' => NULL,
        ],
      ],
      'primary key' => ['id'],
    ];

    $cleantalk_ac_logs_table_schema = [
      'description' => 'AntiCrawler logs.',
      'fields' => [
        'id' => [
          'type' => 'varchar',
          'length' => 40,
          'not null' => TRUE,
          'description' => 'ID.',
        ],
        'ip' => [
          'type' => 'varchar',
          'length' => 40,
          'not null' => TRUE,
          'description' => 'IP.',
        ],
        'ua' => [
          'type' => 'varchar',
          'length' => 40,
          'not null' => TRUE,
          'description' => 'UA.',
        ],
        'entries' => [
          'type' => 'int',
          'length' => 11,
          'description' => 'Entries.',
          'not null' => TRUE,
          'default' => 0,
        ],
        'interval_start' => [
          'type' => 'int',
          'length' => 11,
          'not null' => TRUE,
          'description' => 'interval_start.',
        ],
      ],
      'primary key' => ['id'],
    ];

    $cleantalk_ac_ua_bl_table_schema = [
      'description' => 'AntiCrawler User-Agent Blacklist.',
      'fields' => [
        'id' => [
          'type' => 'int',
          'length' => 11,
          'not null' => TRUE,
          'description' => 'ID.',
        ],
        'ua_template' => [
          'type' => 'varchar',
          'length' => 255,
          'not null' => FALSE,
        ],
        'ua_status' => [
          'type' => 'int',
          'length' => 1,
          'not null' => FALSE,
        ],
      ],
      'indexes' => [
        'network' => ['ua_template'],
      ],
      'primary key' => ['id'],
    ];

    \Drupal::service('database')->schema()->createTable('cleantalk_sfw', $cleantalk_sfw_table_schema);
    \Drupal::service('database')->schema()->createTable('cleantalk_sfw_logs', $cleantalk_sfw_logs_table_schema);
    \Drupal::service('database')->schema()->createTable('cleantalk_ac_logs', $cleantalk_ac_logs_table_schema);
    \Drupal::service('database')->schema()->createTable('cleantalk_ua_bl', $cleantalk_ac_ua_bl_table_schema);

    /** @var \Cleantalk\Common\Cron\Cron $cron_class */
    $cron_class = Mloader::get('Cron');
    $cron = new $cron_class();
    $cron->saveTasks($cron->getDefaultTasks());
  }
}
