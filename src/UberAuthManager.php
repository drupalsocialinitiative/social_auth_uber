<?php

namespace Drupal\social_auth_uber;

use Drupal\social_auth\AuthManager\OAuth2Manager;
use Drupal\Core\Config\ConfigFactory;
use Drupal\Core\Logger\LoggerChannelFactoryInterface;
use Drupal\Core\Entity\EntityFieldManagerInterface;
use Drupal\Core\Routing\UrlGeneratorInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;

/**
 * Contains all the logic for Uber login integration.
 */
class UberAuthManager extends OAuth2Manager {

  /**
   * The logger channel.
   *
   * @var \Drupal\Core\Logger\LoggerChannelFactoryInterface
   */
  protected $loggerFactory;

  /**
   * The event dispatcher.
   *
   * @var \Symfony\Component\EventDispatcher\EventDispatcherInterface
   */
  protected $eventDispatcher;

  /**
   * The entity field manager.
   *
   * @var \Drupal\Core\Entity\EntityFieldManagerInterface
   */
  protected $entityFieldManager;

  /**
   * The url generator.
   *
   * @var \Drupal\Core\Routing\UrlGeneratorInterface
   */
  protected $urlGenerator;

  /**
   * The Uber client object.
   *
   * @var \League\OAuth2\Client\Provider\Uber
   */
  protected $client;
  /**
   * The Uber access token.
   *
   * @var \League\OAuth2\Client\Token\AccessToken
   */
  protected $token;

  /**
   * The Uber user.
   *
   * @var \League\OAuth2\Client\Provider\UberUser
   */
  protected $user;

  /**
   * The data point to be collected.
   *
   * @var string
   */
  protected $scopes;

  /**
   * Social Auth Uber Settings.
   *
   * @var array
   */
  protected $settings;


  /**
   * Constructor.
   *
   * @param \Drupal\Core\Logger\LoggerChannelFactoryInterface $logger_factory
   *   Used for logging errors.
   * @param \Symfony\Component\EventDispatcher\EventDispatcherInterface $event_dispatcher
   *   Used for dispatching events to other modules.
   * @param \Drupal\Core\Entity\EntityFieldManagerInterface $entity_field_manager
   *   Used for accessing Drupal user picture preferences.
   * @param \Drupal\Core\Routing\UrlGeneratorInterface $url_generator
   *   Used for generating absoulute URLs.
   * @param \Drupal\Core\Config\ConfigFactory $configFactory
   *   Used for accessing configuration object factory.
   */
  public function __construct(LoggerChannelFactoryInterface $logger_factory, EventDispatcherInterface $event_dispatcher, EntityFieldManagerInterface $entity_field_manager, UrlGeneratorInterface $url_generator, ConfigFactory $configFactory) {
    $this->loggerFactory      = $logger_factory;
    $this->eventDispatcher    = $event_dispatcher;
    $this->entityFieldManager = $entity_field_manager;
    $this->urlGenerator       = $url_generator;
    $this->config             = $configFactory->getEditable('social_auth_uber.settings');
  }

  /**
   * Authenticates the users by using the access token.
   *
   * @return $this
   *   The current object.
   */
  public function authenticate() {
    $this->token = $this->client->getAccessToken('authorization_code',
      ['code' => $_GET['code']]);
  }

  /**
   * Gets the data by using the access token returned.
   *
   * @return League\OAuth2\Client\Provider\UberUser
   *   User info returned by the Uber.
   */
  public function getUserInfo() {
    $this->user = $this->client->getResourceOwner($this->token);
    return $this->user;
  }

  /**
   * Gets the data by using the access token returned.
   *
   * @return string
   *   Data returned by Making API Call.
   */
  public function getExtraDetails($url) {
    if($url) {
      $httpRequest = $this->client->getAuthenticatedRequest('GET', $url, $this->token, []);
      $data = $this->client->getResponse($httpRequest);
      return json_decode($data->getBody(), true);
    }
  }

  /**
   * Returns the Uber login URL where user will be redirected.
   *
   * @return string
   *   Absolute Uber login URL where user will be redirected
   */
  public function getUberLoginUrl() {
    $scopes = ['profile'];

    $login_url = $this->client->getAuthorizationUrl();

    // Generate and return the URL where we should redirect the user.
    return $login_url;
  }

  /**
   * Returns the Uber login URL where user will be redirected.
   *
   * @return string
   *   Absolute Uber login URL where user will be redirected
   */
  public function getState() {
    $state = $this->client->getState();

    // Generate and return the URL where we should redirect the user.
    return $state;
  }


}