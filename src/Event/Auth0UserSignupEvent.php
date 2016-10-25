<?php
namespace Drupal\auth0\Event;

use Symfony\Component\EventDispatcher\Event;

class Auth0UserSignupEvent extends Event {

  const NAME = 'auth0.signup';

  protected $user;
  protected $auth0Profile;

  public function __construct($user, $auth0_profile) {
    $this->user = $user;
    $this->auth0Profile = $auth0_profile;
  }

  public function getUser() {
    return $this->user;
  }

  public function getAuth0Profile() {
    return $this->auth0Profile;
  }

}
