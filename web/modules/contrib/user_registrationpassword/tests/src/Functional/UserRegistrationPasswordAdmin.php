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
class UserRegistrationPasswordAdmin extends BrowserTestBase {

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * Modules to install.
   *
   * @var array
   */
  protected static $modules = ['user_registrationpassword'];

  /**
   * The admin user.
   *
   * @var \Drupal\user\Entity\User
   */
  protected $adminUser;

  /**
   * A regular user.
   *
   * @var \Drupal\user\Entity\User
   */
  protected $regularUser;

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    // User to add and remove language.
    $this->adminUser = $this->drupalCreateUser(['administer account settings', 'administer users']);
    // User to check non-admin access.
    // @todo This user is not used in the test.
    $this->regularUser = $this->drupalCreateUser();
  }

  /**
   * Implements testRegistrationWithEmailVerificationAndPasswordAdmin().
   */
  public function testRegistrationWithEmailVerificationAndPasswordAdmin() {
    // Login with admin user.
    $this->drupalLogin($this->adminUser);

    // Test the default options.
    $this->drupalGet('admin/config/people/accounts');
    $edit_first = [
      'user_register' => UserInterface::REGISTER_VISITORS,
      'user_registrationpassword_registration' => UserRegistrationPassword::VERIFICATION_PASS,
    ];
    $this->drupalGet('admin/config/people/accounts');
    $this->submitForm($edit_first, 'Save configuration');

    // Load config.
    $user_config = \Drupal::configFactory()->get('user.settings');
    // Variable verify_mail.
    $this->assertFalse($user_config->get('verify_mail'), 'Variable verify_mail set correctly.');
    // Variable notify.register_pending_approval.
    $this->assertFalse($user_config->get('notify.register_pending_approval'), 'Variable notify.register_pending_approval set correctly.');
    // Variable notify.register_no_approval_required.
    $this->assertFalse($user_config->get('notify.register_no_approval_required'), 'Variable notify.register_no_approval_required set correctly.');

    // Test the admin approval option.
    $this->drupalGet('admin/config/people/accounts');
    $edit_second = [
      'user_register' => UserInterface::REGISTER_VISITORS_ADMINISTRATIVE_APPROVAL,
      'user_registrationpassword_registration' => UserRegistrationPassword::VERIFICATION_PASS,
    ];
    $this->drupalGet('admin/config/people/accounts');
    $this->submitForm($edit_second, 'Save configuration');

    // Load config.
    $user_config = \Drupal::configFactory()->get('user.settings');
    // Variable verify_mail.
    $this->assertTrue($user_config->get('verify_mail'), 'Variable verify_mail set correctly.');
    // Variable notify.register_pending_approval.
    $this->assertTrue($user_config->get('notify.register_pending_approval'), 'Variable notify.register_pending_approval set correctly.');
    // Variable notify.register_no_approval_required.
    $this->assertTrue($user_config->get('notify.register_no_approval_required'), 'Variable notify.register_no_approval_required set correctly.');

    // Test the admin only option.
    $this->drupalGet('admin/config/people/accounts');
    $edit_third = [
      'user_register' => UserInterface::REGISTER_ADMINISTRATORS_ONLY,
      'user_registrationpassword_registration' => UserRegistrationPassword::VERIFICATION_PASS,
    ];
    $this->drupalGet('admin/config/people/accounts');
    $this->submitForm($edit_third, 'Save configuration');

    // Load config.
    $user_config = \Drupal::configFactory()->get('user.settings');
    // Variable verify_mail.
    $this->assertTrue($user_config->get('verify_mail'), 'Variable verify_mail set correctly.');
    // Variable notify.register_pending_approval.
    $this->assertFalse($user_config->get('notify.register_pending_approval'), 'Variable notify.register_pending_approval set correctly.');
    // Variable notify.register_no_approval_required.
    $this->assertFalse($user_config->get('notify.register_no_approval_required'), 'Variable notify.register_no_approval_required set correctly.');
  }

}
