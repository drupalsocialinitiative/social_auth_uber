<?php

namespace Drupal\social_auth_uber\Settings;

/**
 * Defines an interface for Social Auth Uber settings.
 */
interface UberAuthSettingsInterface {

  /**
   * Gets the client ID.
   *
   * @return string
   *   The client ID.
   */
  public function getClientId();

  /**
   * Gets the client secret.
   *
   * @return string
   *   The client secret.
   */
  public function getClientSecret();

}
