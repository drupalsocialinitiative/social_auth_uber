<?php

namespace Drupal\social_auth_uber\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\social_api\Plugin\NetworkManager;
use Drupal\social_auth\SocialAuthDataHandler;
use Drupal\social_auth\SocialAuthUserManager;
use Drupal\social_auth_uber\UberAuthManager;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Drupal\Core\Routing\TrustedRedirectResponse;
use Symfony\Component\HttpFoundation\RequestStack;
use Drupal\Core\Logger\LoggerChannelFactoryInterface;

/**
 * Returns responses for Simple Uber Connect module routes.
 */
class UberAuthController extends ControllerBase {

  /**
   * The network plugin manager.
   *
   * @var \Drupal\social_api\Plugin\NetworkManager
   */
  private $networkManager;

  /**
   * The user manager.
   *
   * @var \Drupal\social_auth\SocialAuthUserManager
   */
  private $userManager;

  /**
   * The Uber authentication manager.
   *
   * @var \Drupal\social_auth_uber\UberAuthManager
   */
  private $uberManager;

  /**
   * Used to access GET parameters.
   *
   * @var \Symfony\Component\HttpFoundation\RequestStack
   */
  private $request;

  /**
   * The Social Auth Data Handler.
   *
   * @var \Drupal\social_auth\SocialAuthDataHandler
   */
  private $dataHandler;


  /**
   * The logger channel.
   *
   * @var \Drupal\Core\Logger\LoggerChannelFactoryInterface
   */
  protected $loggerFactory;

  /**
   * UberAuthController constructor.
   *
   * @param \Drupal\social_api\Plugin\NetworkManager $network_manager
   *   Used to get an instance of social_auth_uber network plugin.
   * @param \Drupal\social_auth\SocialAuthUserManager $user_manager
   *   Manages user login/registration.
   * @param \Drupal\social_auth_uber\UberAuthManager $uber_manager
   *   Used to manage authentication methods.
   * @param \Symfony\Component\HttpFoundation\RequestStack $request
   *   Used to access GET parameters.
   * @param \Drupal\social_auth\SocialAuthDataHandler $social_auth_data_handler
   *   SocialAuthDataHandler object.
   * @param \Drupal\Core\Logger\LoggerChannelFactoryInterface $logger_factory
   *   Used for logging errors.
   */
  public function __construct(NetworkManager $network_manager,
                              SocialAuthUserManager $user_manager,
                              UberAuthManager $uber_manager,
                              RequestStack $request,
                              SocialAuthDataHandler $social_auth_data_handler,
                              LoggerChannelFactoryInterface $logger_factory) {

    $this->networkManager = $network_manager;
    $this->userManager = $user_manager;
    $this->uberManager = $uber_manager;
    $this->request = $request;
    $this->dataHandler = $social_auth_data_handler;
    $this->loggerFactory = $logger_factory;

    // Sets the plugin id.
    $this->userManager->setPluginId('social_auth_uber');

    // Sets the session keys to nullify if user could not logged in.
    $this->userManager->setSessionKeysToNullify(['access_token', 'oauth2state']);
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    return new static(
      $container->get('plugin.network.manager'),
      $container->get('social_auth.user_manager'),
      $container->get('social_auth_uber.manager'),
      $container->get('request_stack'),
      $container->get('social_auth.data_handler'),
      $container->get('logger.factory')
    );
  }

  /**
   * Response for path 'user/login/uber'.
   *
   * Redirects the user to Uber for authentication.
   */
  public function redirectToUber() {
    /* @var \Stevenmaguire\OAuth2\Client\Provider\Uber|false $uber */
    $uber = $this->networkManager->createInstance('social_auth_uber')->getSdk();

    // If Uber client could not be obtained.
    if (!$uber) {
      drupal_set_message($this->t('Social Auth Uber not configured properly. Contact site administrator.'), 'error');
      return $this->redirect('user.login');
    }

    // Uber client was returned, inject it to $uberManager.
    $this->uberManager->setClient($uber);

    // Generates the URL where the user will be redirected for authorization.
    $login_url = $this->uberManager->getAuthorizationUrl();

    $state = $this->uberManager->getState();

    $this->dataHandler->set('oauth2state', $state);

    return new TrustedRedirectResponse($login_url);
  }

  /**
   * Response for path 'user/login/uber/callback'.
   *
   * Uber returns the user here after user has authenticated in Uber.
   */
  public function callback() {
    // Checks if user cancel login via Uber.
    $error = $this->request->getCurrentRequest()->get('error');
    if ($error == 'access_denied') {
      drupal_set_message($this->t('You could not be authenticated.'), 'error');
      return $this->redirect('user.login');
    }

    /* @var \Stevenmaguire\OAuth2\Client\Provider\Uber|false $uber */
    $uber = $this->networkManager->createInstance('social_auth_uber')->getSdk();

    // If Uber client could not be obtained.
    if (!$uber) {
      drupal_set_message($this->t('Social Auth Uber not configured properly. Contact site administrator.'), 'error');
      return $this->redirect('user.login');
    }

    $state = $this->dataHandler->get('oauth2state');

    // Retrieves $_GET['state'].
    $retrievedState = $this->request->getCurrentRequest()->query->get('state');
    if (empty($retrievedState) || ($retrievedState !== $state)) {
      $this->userManager->nullifySessionKeys();
      drupal_set_message($this->t('Uber login failed. Unvalid OAuth2 State.'), 'error');
      return $this->redirect('user.login');
    }

    $this->uberManager->setClient($uber)->authenticate();

    // Saves access token to session.
    $this->dataHandler->set('access_token', $this->uberManager->getAccessToken());

    // Gets user's info from Uber API.
    /* @var \Stevenmaguire\OAuth2\Client\Provider\UberResourceOwner $profile */
    if (!$profile = $this->uberManager->getUserInfo()) {
      drupal_set_message($this->t('Uber login failed, could not load Uber profile. Contact site administrator.'), 'error');
      return $this->redirect('user.login');
    }

    // Gets (or not) extra initial data.
    $data = $this->userManager->checkIfUserExists($profile->getId()) ? NULL : $this->uberManager->getExtraDetails();

    // If user information could be retrieved.
    return $this->userManager->authenticateUser($profile->getFirstname() . ' ' . $profile->getLastname(), $profile->getEmail(), $profile->getId(), $this->uberManager->getAccessToken(), $profile->getImageurl(), $data);

  }

}
