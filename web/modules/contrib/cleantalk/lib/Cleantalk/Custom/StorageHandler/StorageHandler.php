<?php

namespace Cleantalk\Custom\StorageHandler;

use Symfony\Component\HttpFoundation\Request;

class StorageHandler implements \Cleantalk\Common\StorageHandler\StorageHandler
{
  public static $jsLocation;

  public function getSetting($setting_name)
  {
    return \Drupal::state()->get($setting_name);
  }

  public function deleteSetting($setting_name)
  {
    return \Drupal::state()->delete($setting_name);
  }

  public function saveSetting($setting_name, $setting_value)
  {
    \Drupal::state()->set($setting_name, $setting_value);
    return true;
  }

  public static function getUpdatingFolder()
  {
    $request = Request::createFromGlobals();
    $site_files_dir = \Drupal\Core\DrupalKernel::findSitePath($request) . DIRECTORY_SEPARATOR . 'files';
    return $site_files_dir . DIRECTORY_SEPARATOR . 'cleantalk_fw_files' . DIRECTORY_SEPARATOR;
  }

  public static function getJsLocation()
  {
    if ( ! empty( static::$jsLocation ) ) {
      return static::$jsLocation;
    }
    return \Drupal::request()->getSchemeAndHttpHost() .
    \Drupal::service('extension.list.module')->getPath('cleantalk') .
    "/js/apbct-functions.js";
  }
}
