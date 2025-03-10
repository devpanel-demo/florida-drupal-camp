<?php

namespace Drupal\Tests\user_registrationpassword\Functional;

use Drupal\Tests\BrowserTestBase;
use Drupal\user\UserInterface;
use Drupal\user_registrationpassword\UserRegistrationPassword;

/**
 * Functionality tests for User registration password module.
 *
 * @group user_registrationpassword
 */
class UserRegistrationPasswordUserRegisterForm extends BrowserTestBase {

  /**
   * Modules to install.
   *
   * @var array
   */
  protected static $modules = ['user_registrationpassword'];

  /**
   * The registration form.
   *
   * @var object
   */
  protected $registerForm;

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();

    $user_config = \Drupal::configFactory()->getEditable('user.settings');
    $config = \Drupal::configFactory()->getEditable('user_registrationpassword.settings');

    $user_config->set('register', UserInterface::REGISTER_VISITORS)->save();
    $config->set('registration', UserRegistrationPassword::VERIFICATION_PASS)->save();

    // Create a new user entity.
    $entity = \Drupal::entityTypeManager()
      ->getStorage('user')
      ->create([]);

    // Build a form object for the user: register form.
    $formObject = \Drupal::entityTypeManager()
      ->getFormObject('user', 'register')
      ->setEntity($entity);

    // Build the form.
    $this->registerForm = \Drupal::formBuilder()->getForm($formObject);
  }

  /**
   * Implements testUserRegisterFormDefaultValues().
   */
  public function testUserRegisterFormDefaultValues() {
    // Test values.
    $this->assertTrue(is_int($this->registerForm['account']['status']['#default_value']), 'The default value for status is an integer.');
    $this->assertTrue(is_bool($this->registerForm['account']['notify']['#default_value']), 'The default value for notify is a boolean.');
  }

  /**
   * Implements testUserRegisterFormCompatibility().
   */
  public function testUserRegisterFormCompatibility() {
    // Test submit callback.
    $this->assertEquals($this->registerForm['actions']['submit']['#submit'][2], 'user_registrationpassword_form_user_register_submit', 'Submit handler correctly changed.');
  }

}
