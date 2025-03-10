<?php

namespace Drupal\youtube\Plugin\Field\FieldFormatter;

use Drupal\Component\Utility\Html;
use Drupal\Core\Field\FieldItemListInterface;
use Drupal\Core\Field\FormatterBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Url;

/**
 * Plugin implementation of the 'youtube_url' formatter.
 *
 * @FieldFormatter(
 *   id = "youtube_url",
 *   label = @Translation("YouTube URL"),
 *   field_types = {
 *     "youtube"
 *   }
 * )
 */
class YouTubeUrlFormatter extends FormatterBase {

  /**
   * {@inheritdoc}
   */
  public static function defaultSettings() {
    return [
      'link' => TRUE,
    ] + parent::defaultSettings();
  }

  /**
   * {@inheritdoc}
   */
  public function settingsForm(array $form, FormStateInterface $form_state) {
    $elements = parent::settingsForm($form, $form_state);

    $elements['link'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Output this field as a link'),
      '#default_value' => $this->getSetting('link'),
    ];

    return $elements;
  }

  /**
   * {@inheritdoc}
   */
  public function settingsSummary() {
    $summary = [];
    $link = $this->getSetting('link');

    if ($link) {
      $summary[] = $this->t('YouTube URL as a link.');
    }
    else {
      $summary[] = $this->t('YouTube URL as plain text.');
    }

    return $summary;
  }

  /**
   * {@inheritdoc}
   */
  public function prepareView(array $entities_items) {}

  /**
   * {@inheritdoc}
   */
  public function viewElements(FieldItemListInterface $items, $langcode) {
    $element = [];
    $link = $this->getSetting('link');

    foreach ($items as $delta => $item) {
      if ($link) {
        $element[$delta] = [
          '#type' => 'link',
          '#title' => $item->input,
          '#url' => Url::fromUri($item->input),
          '#options' => [
            'attributes' => [
              'class' => [
                'youtube-url',
                'youtube-url--' . Html::getClass($item->video_id),
              ],
            ],
            'html' => TRUE,
          ],
        ];
      }
      else {
        $element[$delta] = [
          '#markup' => Html::escape($item->input),
        ];
      }
    }

    return $element;
  }

}
