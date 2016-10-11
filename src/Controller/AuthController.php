<?php
/**
 * @file
 * Contains \Drupal\auth0\Controller\AuthController.
 */

namespace Drupal\auth0\Controller;

require_once (AUTH0_PATH . '/vendor/autoload.php');

use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Url;
use Drupal\user\Entity\User;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RedirectResponse;

use Auth0SDK\Auth0;

/**
 * Controller routines for auth0 routes.
 */
class AuthController extends ControllerBase {

  /**
   * Handles the login page override
   */
  public function login() {
    global $base_root;

    $config = \Drupal::service('config.factory')->get('auth0.settings');

    $lockExtraSettings = $config->get('auth0_lock_extra_settings');

    if (trim($lockExtraSettings) == "") {
      $lockExtraSettings = "{}";
    }

    return array(
      '#theme' => 'auth0_login',
      '#domain' => $config->get('auth0_domain'),
      '#clientID' => $config->get('auth0_client_id'),
      '#state' => null,
      '#showSignup' => $config->get('auth0_allow_signup'),
      '#widgetCdn' => $config->get('auth0_widget_cdn'),
      '#loginCSS' => $config->get('auth0_login_css'),
      '#lockExtraSettings' => $lockExtraSettings,
      '#callbackURL' => "$base_root/auth0/callback",
    );

  }

  /**
   * Handles the callback for the oauth transaction
   */
  public function callback(Request $request) {
    global $base_root;

    $config = \Drupal::service('config.factory')->get('auth0.settings');

    $auth0 = new Auth0(array(
        'domain'        => $config->get('auth0_domain'),
        'client_id'     => $config->get('auth0_client_id'),
        'client_secret' => $config->get('auth0_client_secret'),
        'redirect_uri'  => "$base_root/auth0/callback",
        'store'         => false
    ));

    $userInfo = null;

    try {
        $userInfo = $auth0->getUserInfo();
        $idToken = $auth0->getIdToken();
    } catch(Exception $e) {

    }

    if ($userInfo) {
      return $this->auth0_login_auth0_user($request, $userInfo, $idToken);
    } else {
      drupal_set_message(t('There was a problem logging you in, sorry by the inconvenience.'),'error');

      return new RedirectResponse('/');
    }
  }

  protected function auth0_login_auth0_user(Request $request, $userInfo, $idToken) {
    $config = \Drupal::service('config.factory')->get('auth0.settings');
    $requires_email = $config->get('auth0_requires_verified_email');
    
    if ($requires_email) {
        if (!isset($userInfo['email']) || empty($userInfo['email'])) {
            drupal_set_message(
                t('This account does not have an email associated. Please login with a different provider.'),
                'error'
            );

            return new RedirectResponse('/');
        }
        if (!$userInfo['email_verified']) {
          return $this->auth0_fail_with_verify_email($idToken);
        }
    }

    // See if there is a user in the auth0_user table with the user info client id
    $user = $this->auth0_find_auth0_user($userInfo['user_id']);
    
    if ($user) {
        // User exists!
        // update the auth0_user with the new userInfo object
        $this->auth0_update_auth0_object($userInfo);

        // Update field and role mappings
        $this->auth0_update_fields_and_roles($userInfo, $user);

      user_login_finalize($user);
    } else {
        // If the user doesn't exist we need to either create a new one, or assign him to an existing one
       // If the user doesn't exist we need to either create a new one, or assign him to an existing one
        $isDatabaseUser = false;
        foreach ($userInfo['identities'] as $identity) {
            if ($identity['provider'] == "auth0") {
                $isDatabaseUser = true;
            }
        }
        $joinUser = false;
        // If the user has a verified email or is a database user try to see if there is
        // a user to join with. The isDatabase is because we don't want to allow database
        // user creation if there is an existing one with no verified email
        if ($userInfo['email_verified'] || $isDatabaseUser) {
            $joinUser = user_load_by_mail($userInfo['email']);
        }

        if ($joinUser) { 
          // If we are here, we have a potential join user
          // Don't allow creation or assignation of user if the email is not verified, that would
          // be hijacking
          if (!$userInfo['email_verified']) {
            return $this->auth0_fail_with_verify_email($idToken);
          }
          $user = $joinUser;
        } else {
          // If we are here, we need to create the user
          $user = $this->auth0_create_user_from_auth0($userInfo);
        }

        $this->auth0_insert_auth0_user($userInfo, $user->id());

        // Update field and role mappings
        $this->auth0_update_fields_and_roles($userInfo, $user);

        user_login_finalize($user);

        // A destination was set, probably on an exception controller,
    }

    if ($request->request->has('destination')) {
      return $this->redirect($request->request->get('destination'));
    }

    return $this->redirect('entity.user.canonical', array('user' => $user->id()));
  }

  protected function auth0_fail_with_verify_email($idToken) {

    $url = Url::fromRoute('auth0.verify_email', array(), array("query" => array('token' => $idToken)));

    drupal_set_message(
      t("Please verify your email and log in again. Click <a href=@url>here</a> to Resend verification email.", 
        array(
          '@url' => $url->toString()
        )
    ), 'warning');


    return new RedirectResponse('/');
  }

  protected function auth0_find_auth0_user($id) {
    $rs = db_select('auth0_user', 'a')
        ->fields('a', array('drupal_id'))
        ->condition('auth0_id', $id, '=')
        ->execute()
        ->fetchAssoc();

    return empty($rs) ? false : User::load($rs['drupal_id']);
  }

  protected function auth0_update_auth0_object($userInfo) {
      db_update('auth0_user')
          ->fields(array(
              'auth0_object' => serialize($userInfo)
          ))
          ->condition('auth0_id', $userInfo['user_id'], '=')
          ->execute();
  }

  protected function auth0_update_fields_and_roles($userInfo, $user) {
    function_exists('dd') && dd($userInfo, 'auth0_update_fields_and_roles called with userInfo');
    function_exists('dd') && dd($user, 'auth0_update_fields_and_roles called with user');

    $edit = array();
    $this->auth0_update_fields($userInfo, $user, $edit);
    $this->auth0_update_roles($userInfo, $user, $edit);
//
    function_exists('dd') && dd($edit, 'values to edit');
    $user->save();
//    user_save($the_user, $edit);
//    //cache_clear_all('menu:'. $uid, TRUE);

    //function_exists('dd') && dd(user_load($user->get('uid')), 'the_user after updates');
  }

  /*
   * Update the $user profile attributes of a user based on the auth0 field mappings
   */
  protected function auth0_update_fields($user_info, $user, &$edit)
  {
    $config = \Drupal::service('config.factory')->get('auth0.settings');
    $auth0_claim_mapping = $config->get('auth0_claim_mapping');
    function_exists('dd') && dd($auth0_claim_mapping, 'auth0_claim_mapping');

    if (isset($auth0_claim_mapping) && !empty($auth0_claim_mapping)) {
      // For each claim mapping, lookup the value, otherwise set to blank
      $mappings = $this->auth0_pipeListToArray($auth0_claim_mapping);
      function_exists('dd') && dd($mappings, 'auth0_claim_mapping as array');

      // Remove mappings handled automatically by the module
      $skip_mappings = array('uid', 'name', 'mail', 'init', 'is_new', 'status', 'pass');
      foreach ($mappings as $mapping) {
        function_exists('dd') && dd($mapping, 'mapping');

        $key = $mapping[1];
        if (in_array($key, $skip_mappings)) {
          function_exists('dd') && dd($mapping, 'skipping mapping handled already by auth0 module');
        } else {
          $value = isset($user_info[$mapping[0]]) ? $user_info[$mapping[0]] : '';
          $current_value = $user->get($key)->value;
          if ($current_value === $value) {
            function_exists('dd') && dd($key, 'value is unchanged');
          } else {
            function_exists('dd') && dd($key . ' from [' . $current_value . '] to [' . $value . ']', 'value changed');
            $edit[$key] = $value;
            $user->set($key, $value);
          }
        }
      }
    }
  }

  /**
   * Updates the $user->roles of a user based on the auth0 role mappings
   */
  protected function auth0_update_roles($user_info, $user, &$edit)
  {
    $config = \Drupal::service('config.factory')->get('auth0.settings');
    $auth0_claim_to_use_for_role = $config->get('auth0_claim_to_use_for_role');
    if (isset($auth0_claim_to_use_for_role) && !empty($auth0_claim_to_use_for_role)) {
      $claim_value = isset($user_info[$auth0_claim_to_use_for_role]) ? $user_info[$auth0_claim_to_use_for_role] : '';
      function_exists('dd') && dd($claim_value, 'claim_value');

      $claim_values = array();
      if (is_array($claim_value)) {
        $claim_values = $claim_value;
      } else {
        $claim_values[] = $claim_value;
      }
      function_exists('dd') && dd($claim_values, 'claim_values');

      $auth0_role_mapping = $config->get('auth0_role_mapping');
      $mappings = $this->auth0_pipeListToArray($auth0_role_mapping);
      function_exists('dd') && dd($mappings, 'auth0_role_mapping as array');

      $roles_granted = array();
      $roles_managed_by_mapping = array();
      foreach ($mappings as $mapping) {
        function_exists('dd') && dd($mapping, 'mapping');
        $roles_managed_by_mapping[] = $mapping[1];

        if (in_array($mapping[0], $claim_values)) {
          $roles_granted[] = $mapping[1];
        }
      }
      $roles_granted = array_unique($roles_granted);
      $roles_managed_by_mapping = array_unique($roles_managed_by_mapping);
      function_exists('dd') && dd($roles_granted, 'roles_granted');
      function_exists('dd') && dd($roles_managed_by_mapping, 'roles_managed_by_mapping');

      $not_granted = array_diff($roles_managed_by_mapping, $roles_granted);
      function_exists('dd') && dd($not_granted, 'not_granted');

      $user_roles = $user->getRoles();
      function_exists('dd') && dd($user_roles, 'user_roles');

      $new_user_roles = array_merge(array_diff($user_roles, $not_granted), $roles_granted);
      function_exists('dd') && dd($new_user_roles, 'new_user_roles');

      $tmp = array_diff($new_user_roles, $user_roles);
      if (empty($tmp)) {
        function_exists('dd') && dd('no changes to roles detected');
      } else {
        function_exists('dd') && dd($new_user_roles, 'changes to roles detected');
        $edit['roles'] = $new_user_roles;
        foreach (array_diff($new_user_roles, $user_roles) as $new_role) {
          $user->addRole($new_role);
        }
        foreach (array_diff($user_roles, $new_user_roles) as $remove_role) {
          $user->removeRole($remove_role);
        }
      }
    }
  }

  protected function auth0_mappingsToPipeList($mappings) {
    $result_text = "";
    foreach ($mappings as $map) {
      $result_text .= $map['from'] . '|' . $map['user_entered'] . "\n";
    }
    return $result_text;
  }

  protected function auth0_pipeListToArray($mapping_list_txt, $make_item0_lowercase = FALSE) {
    $result_array = array();
    $mappings = preg_split('/[\n\r]+/', $mapping_list_txt);
    foreach ($mappings as $line) {
      if (count($mapping = explode('|', trim($line))) == 2) {
        $item_0 = ($make_item0_lowercase) ? drupal_strtolower(trim($mapping[0])) : trim($mapping[0]);
        $result_array[] = array($item_0, trim($mapping[1]));
      }
    }
    return $result_array;
  }


  protected function auth0_insert_auth0_user ($userInfo, $uid) {

    db_insert('auth0_user')->fields(array(
        'auth0_id' => $userInfo['user_id'],
        'drupal_id' => $uid,
        'auth0_object' => json_encode($userInfo) 
      ))->execute();

  }

  protected function auth0_create_user_from_auth0 ($userInfo) {

    $language = \Drupal::languageManager()->getCurrentLanguage()->getId();
    $user = User::create();

    $user->setPassword(uniqid('auth0', true));
    $user->enforceIsNew();

    if (isset($userInfo['email']) && !empty($userInfo['email'])) {
        $user->setEmail($userInfo['email']);
    } else {
        $user->setEmail("change_this_email@" . uniqid() .".com");
    }

    // If the username already exists, create a new random one
    $username = $userInfo['nickname'];
    if (user_load_by_name($username)) {
        $username .= time();
    }

    $user->setUsername($username);
    $user->activate();
    $user->save();

    return $user;
  }

  public function verify_email(Request $request) {
    $token = $request->get('token') ;

    $config = \Drupal::service('config.factory')->get('auth0.settings');
    $secret = $config->get('auth0_client_secret');

    try {
      $user = \JWT::decode($token, base64_decode(strtr($secret, '-_', '+/')) );

      $userId = $user->sub;
      $domain = $config->get('auth0_domain');
      $url = "https://$domain/api/users/$userId/send_verification_email";
      
      $client = \Drupal::httpClient();
      
      $response = $client->request('POST', $url, array( "headers" => array(
        "Authorization" => "Bearer $token"
      )));

      drupal_set_message(t('An Authorization email was sent to your account'));
    } 
    catch(\UnexpectedValueException $e) {
       drupal_set_message(t('Your session has expired.'),'error');
    }
    catch(Exception $e) {
       drupal_set_message(t('Sorry, we couldnt send the email'),'error');
    }

    return new RedirectResponse('/');
  }
}