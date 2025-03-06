<?php

namespace Cleantalk\Custom\Db;

class Schema extends \Cleantalk\Common\Db\Schema
{
  /**
   * Structure of schema
   *
   * @var array
   */
  private static $structureSchemas = [
    'cleantalk_timelabels' => [
      'description' => 'Timelabels for admin notification sending.',
      'fields' => [
        'ct_key' => [
          'type' => 'varchar',
          'length' => 100,
          'not null' => TRUE,
          'default' => '',
          'description' => 'Notification ID.',
        ],
        'ct_value' => [
          'type' => 'int',
          'length' => 12,
          'unsigned' => TRUE,
          'not null' => TRUE,
          'default' => 0,
          'description' => 'Time of last notification.',
        ],
      ],
      'primary key' => [
        'ct_key',
      ],
    ],
    'cleantalk_sfw' => [
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
      'primary key' => [
        'id',
      ],
    ],
    'cleantalk_sfw_logs' => [
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
    ],
    'cleantalk_ac_logs' => [
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
    ],
    'cleantalk_ua_bl' => [
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
    ],
    'cleantalk_sessions' => [
      'description' => 'Alternative cookies table',
      'fields' => [
        'id' => [
          'type' => 'varchar',
          'length' => 64,
          'not null' => TRUE,
          'description' => 'id.',
        ],
        'name' => [
          'type' => 'varchar',
          'length' => 40,
          'not null' => TRUE,
          'default' => '',
          'description' => 'name.',
        ],
        'value' => [
          'type' => 'text',
          'not null' => FALSE,
          'default' => NULL,
          'description' => 'value.',
        ],
        'last_update' => [
          'type' => 'datetime',
          'mysql_type' => 'datetime',
          'pgsql_type' => 'timestamp',
          'not null' => FALSE,
          'default' => NULL,
          'description' => 'time().',
        ],
      ],
      'primary key' => [
        'id',
        'name',
      ],
    ],
  ];

  /**
   * Return $structure_schemas
   */
  public static function getStructureSchemas() {
    return static::$structureSchemas;
  }

}
