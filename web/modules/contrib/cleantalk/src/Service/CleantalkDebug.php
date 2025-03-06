<?php

namespace Drupal\cleantalk\Service;

class CleantalkDebug
{
    /**
     * Collect all debug data to Drupal state.
     * @return void
     */
    public static function collectData(): void
    {
        $data = array(
            'sfw_data' => self::getSFWdata(),
            'state_data' => self::getCommonData(),
            'cron_data' => self::getCronData(),
            'plugin_settings' => self::getPluginSettings()
        );
        self::saveData($data);
    }

    /**
     * Save debug data to Drupal state.
     * @param array $data
     * @return void
     */
    private static function saveData(array $data): void
    {
        \Drupal::state()->set('cleantalk_debug_data', $data);
    }

    /**
     * Get debug data from Drupal state.
     * @return mixed
     */
    private static function loadData()
    {
        return \Drupal::state()->get('cleantalk_debug_data');
    }

    /**
     * Scan Drupal state to find keys values.
     * @param $keys
     * @return array
     */
    private static function scanStateForKeys($keys): array
    {
        $result = array();
        foreach ( $keys as $key) {
            if ( \Drupal::state()->get($key) ) {
                $result[$key] = \Drupal::state()->get($key);
            } else {
                $result[$key] = 'no_state_record';
            }
        }
        return $result;
    }

    /**
     * Return JSON string of debug data. Empty string if no data found.
     * @return string
     */
    public static function getDebugJSON(): string
    {
        return empty(self::loadData()) ? '' : json_encode(self::loadData(), JSON_PRETTY_PRINT);
    }

    /**
     * Clear debug data.
     * @return void
     */
    public static function clearDebugData(): void
    {
        self::saveData(array());
    }

    /**
     * Scan Drupal state to find CleanTalk values.
     * @return string[]
     */
    private static function getCommonData(): array
    {
        $keys = array(
            //'cleantalk_api_account_name_ob' => 'no_state_record',
            //'cleantalk_api_user_token' => 'no_state_record',
            'cleantalk_api_ip_license',
            'cleantalk_api_license_trial',
            'cleantalk_api_moderate',
            'cleantalk_api_moderate_ip',
            'cleantalk_api_renew',
            'cleantalk_api_service_id',
            'cleantalk_api_show_notice',
            'cleantalk_api_show_review',
            'cleantalk_api_spam_count',
            'cleantalk_api_trial',
            'cleantalk_remote_calls',
            'cleantalk_show_renew_banner',
            'cleantalk_state',
        );
        return self::scanStateForKeys($keys);
    }

    /**
     * Returns SFW queue and SFW stats.
     * @return array{sfw_update_queue: mixed, apbct_fw_stats: mixed}
     */
    private static function getSFWdata(): array
    {
        return array(
            'sfw_update_queue' => self::scanStateForKeys(['sfw_update_queue']),
            'apbct_fw_stats' => self::scanStateForKeys(['apbct_fw_stats']),
        );
    }

    /**
     * Returns Cron data.
     * @return array
     */
    private static function getCronData(): array
    {
        $keys = array(
            'cleantalk_cron',
            'cleantalk_cron_last_start'
        );
        return self::scanStateForKeys($keys);
    }

    /**
     * Returns settings state on the time before save.
     * @return array
     */
    private static function getPluginSettings(): array
    {
        $result = \Drupal::config('cleantalk.settings')->getRawData();
        unset($result['cleantalk_authkey']);
        unset($result['_core']);
        return $result;
    }


    /**
     * Run "Save as" dialog to save JSON debug as text.
     * @return void
     */
    public static function saveJSONToFile(): void
    {
        $service_id = \Drupal::state()->get('cleantalk_api_service_id');
        $filename = $service_id ? $service_id . '_' : 'unknown_service_id_';
        $filename .= date('YmdHs') . '_cleantalk_debug_data.txt';
        header('Content-Type: text/csv');
        header("Content-Disposition: attachment; filename=" . $filename);
        echo self::getDebugJSON();
        die();
    }
}
