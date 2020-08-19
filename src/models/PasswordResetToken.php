<?hh // strict

class PasswordResetToken extends Model {
  private function __construct(
    private int $id,
    private int $used,
    private int $team_id,
    private string $token,
    private string $created_ts,
    private String $use_ts,
  ) {}

  public function getId(): int {
    return $this->id;
  }

  public function getUsed(): bool {
    return $this->used === 1;
  }

  public function getTeamId(): int {
    return $this->team_id;
  }

  public function getToken(): string {
    return $this->token;
  }

  public function getCreatedTs(): string {
    return $this->created_ts;
  }

  private static function tokenFromRow(Map<string, string> $row): Token {
    return new Token(
      intval(must_have_idx($row, 'id')),
      intval(must_have_idx($row, 'used')),
      intval(must_have_idx($row, 'team_id')),
      must_have_idx($row, 'token'),
      must_have_idx($row, 'created_ts'),
      must_have_idx($row, 'use_ts'),
    );
  }

  private static function generate(): string {
    $token_len = 15;
    return md5(base64_encode(random_bytes($token_len)));
  }

  // Create token.
  public static async function genCreate(string $email): Awaitable<bool> {
    $db = await self::genDb();
    $tokens = array();
    $query = array();


    $result =
      await $db->queryf(
        'SELECT EXISTS(SELECT team_id FROM teams_data WHERE email = %s)',
        $email,
    );

    if ($result->numRows() > 0) {
      invariant($result->numRows() === 1, 'Expected exactly one result');
      $team_id_exists = intval($result->mapRows()[0]->firstValue());
      if ($team_id_exists === 1) {

        $token = self::generate();

        $host = strval(idx(Utils::getSERVER(), 'HTTP_HOST'));
        $url = "https://" . $host . "/index.php?page=password_reset&token=" . $token;
        $from = "CodePath Support <support@codepath.org>"; # TODO move to config

        $to = $email;
        $subject = "CTF Password Reset Request";
        $txt = "Hello, use this link to reset your password for the CTF platform: " . $url . "\n\nIf you did not request a password reset, you can ignore this message.";
        $headers = "From: " . $from . "\r\n";

        mail($to,$subject,$txt,$headers);

        # clear out old, unused tokens
        $result = await $db->queryf(
            'DELETE FROM password_reset_tokens WHERE used = 0 AND team_id = (select team_id FROM teams_data where email = %s)',
            $email
        );

        $result = await $db->queryf(
            'INSERT INTO password_reset_tokens (token, created_ts, used, team_id) VALUES (%s, NOW(), 0, (select team_id FROM teams_data where email = %s))',
            $token, $email
        );

        return true;
      } else {
        return false;
      }
    } else {
      #log_error("No team found for email: " . $email);
      return false;
    }

  }


  public static async function genCheck(string $token): Awaitable<bool> {
    $db = await self::genDb();

    $result =
      await $db->queryf(
        'SELECT EXISTS(SELECT * FROM password_reset_tokens WHERE used = 0 AND token = %s)',
        $token,
      );

    if ($result->numRows() > 0) {
      invariant($result->numRows() === 1, 'Expected exactly one result');
      return intval($result->mapRows()[0]->firstValue()) > 0;
    } else {
      return false;
    }
  }

  public static async function genGetTeamId(string $token): Awaitable<int> {
    $db = await self::genDb();

    $result =
      await $db->queryf(
        'SELECT team_id FROM password_reset_tokens WHERE used = 0 AND token = %s',
        $token,
      );

    if ($result->numRows() > 0) {
      invariant($result->numRows() === 1, 'Expected exactly one result');
      return intval($result->mapRows()[0]->firstValue());
    } else {
      return 0;
    }
  }

  // Use a token for a password reset.
  public static async function genUse(
    string $token,
  ): Awaitable<void> {
    $db = await self::genDb();

    await $db->queryf(
      'UPDATE password_reset_tokens SET used = 1, use_ts = NOW() WHERE token = %s LIMIT 1',
      $token,
    );
  }
}
