(function ($) {

  /**
   * Attach the Auth0 Lock widget to the login form.
   */
  Drupal.behaviors.password = {
    attach: function (context, settings) {
      $('#auth0-login-form', context).once(function() {

        var lock = new Auth0Lock(settings.auth0.client_id, settings.auth0.domain, settings.auth0.options);

        lock.show(settings.auth0.show);
      })
    }
  }
})(jQuery);
