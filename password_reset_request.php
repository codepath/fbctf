<?hh // strict

require_once ($_SERVER['DOCUMENT_ROOT'].'/../vendor/autoload.php');

/* HH_IGNORE_ERROR[1002] */
SessionUtils::sessionStart();

class PasswordResetRequest {
  public static async function genProcessPasswordResetRequest(): Awaitable<void> {
    error_log("genProcessPasswordResetRequest")

    $type = idx(Utils::getGET(), 'type');

    if (!is_string($type)) {
      $type = "none";
    }


  }

}

$password_reset = new PasswordResetRequest();
\HH\Asio\join($password_reset ->genPasswordResetRequest());
