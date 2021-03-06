var $ = require('jquery');

function teamNameFormError() {
  $('.el--name')[0].classList.add('form-error');
  $('#name_error')[0].classList.remove('completely-hidden');
  $('.fb-form input[name="team_name"]').on('change', function() {
    $('.el--name')[0].classList.remove('form-error');
    $('#name_error')[0].classList.add('completely-hidden');
  });
}

function teamLoginFormError() {
  $('.el--text')[0].classList.add('form-error');
  $('.el--text')[1].classList.add('form-error');
  $('.fb-form input').on('change', function() {
    $('.el--text')[0].classList.remove('form-error');
    $('.el--text')[1].classList.remove('form-error');
  });
}

function teamPasswordFormError(errortype) {
  if (errortype === 'length') {
    $('.el--password')[0].classList.add('form-error');
    $('#pw_error')[0].classList.remove('completely-hidden');
  }
  if (errortype === 'notmatch') {
    $('.el--password')[1].classList.add('form-error');
    $('#confirm_error')[0].classList.remove('completely-hidden');
  }
  if (errortype === 'toosimple') {
    $('.el--password')[0].classList.add('form-error');
    $('.el--password')[1].classList.add('form-error');
    $('#password_error')[0].classList.remove('completely-hidden');
    $('#strong_pw')[0].classList.remove('completely-hidden');
  }
  $('.fb-form input[type="password"]').on('change', function() {
    if (errortype === 'length') {
      $('.el--password')[0].classList.remove('form-error');
      $('#pw_error')[0].classList.add('completely-hidden');
    }
    if (errortype === 'notmatch') {
      $('.el--password')[1].classList.remove('form-error');
      $('#confirm_error')[0].classList.add('completely-hidden');
    }
    if (errortype === 'toosimple') {
      $('.el--password')[0].classList.remove('form-error');
      $('.el--password')[1].classList.remove('form-error');
      $('#password_error')[0].classList.add('completely-hidden');
    }
  });
}

function teamTokenFormError() {
  $('.el--token')[0].classList.add('form-error');
  $('#token_error')[0].classList.remove('completely-hidden');
  $('.fb-form input[name="token"]').on('change', function() {
    $('#token_error')[0].classList.add('completely-hidden');
    $('.el--token')[0].classList.remove('form-error');
  });
}

function teamLogoFormError() {
  $('.fb-choose-emblem')[0].style.color = 'red';
  $('.fb-choose-emblem').on('click', function() {
    $('.fb-choose-emblem')[0].style.color = '';
  });
}

function emailFormError() {
  $('.el--text')[0].classList.add('form-error');
  $('.fb-form input').on('change', function() {
    $('.el--text')[0].classList.remove('form-error');
  });
}

function passwordResetFormError(errortype) {
  if (errortype === 'length') {
    $('.el--password')[0].classList.add('form-error');
    $('#pw_error')[0].classList.remove('completely-hidden');
  }
  if (errortype === 'notmatch') {
    $('.el--password')[1].classList.add('form-error');
    $('#confirm_error')[0].classList.remove('completely-hidden');
  }
  if (errortype === 'toosimple') {
    $('.el--password')[0].classList.add('form-error');
    $('.el--password')[1].classList.add('form-error');
    $('#password_error')[0].classList.remove('completely-hidden');
    $('#strong_pw')[0].classList.remove('completely-hidden');
  }
  if (errortype === 'tokenerror') {
    $('#token_error')[0].classList.remove('completely-hidden');
  }
  $('.fb-form input[type="password"]').on('change', function() {
    if (errortype === 'length') {
      $('.el--password')[0].classList.remove('form-error');
      $('#pw_error')[0].classList.add('completely-hidden');
    }
    if (errortype === 'notmatch') {
      $('.el--password')[1].classList.remove('form-error');
      $('#confirm_error')[0].classList.add('completely-hidden');
    }
    if (errortype === 'toosimple') {
      $('.el--password')[0].classList.remove('form-error');
      $('.el--password')[1].classList.remove('form-error');
      $('#password_error')[0].classList.add('completely-hidden');
    }
  });
}


function verifyTeamName(context) {
  if (context === 'register') {
    var teamName = String($('.fb-form input[name="team_name"]')[0].value);
    if (teamName.length === 0) {
      teamNameFormError();
      return false;
    } else {
      return teamName;
    }
  }
  if (context === 'login') {
    var teamId = $(".fb-form select option:selected")[0].value;
    return teamId;
  }
}

function verifyTeamPassword() {
  var teamPassword = $('.fb-form input[name="password"]')[0].value;
  if (teamPassword.length === 0) {
    teamPasswordFormError('length');
    return false;
  } else if (verifyTeamPassword.caller.name === 'registerTeam' || verifyTeamPassword.caller.name === 'registerNames') {
    var confirm_password = $('.fb-form input[name="confirm_password"]')[0].value;
    if (teamPassword != confirm_password) {
      teamPasswordFormError('notmatch');
      return false;
    } else {
      return teamPassword;
    }
  } else {
    return teamPassword;
  }
}

function verifyTeamLogo(): {isCustom: boolean, type: string, logo: number, error?: any} {
  try {
    // src is filled in by image preview, see fb-ctf.js
    var customLogoSrc = $('#custom-emblem-preview').attr('src');
    if (customLogoSrc) {
      // parse filetype and get base64 data
      // customLogoSrc should be something like data:image/png;base64,AAAFBfj42Pj4...
      var filetypeBeginIdx = customLogoSrc.indexOf('/') + 1;
      var filetypeEndIdx = customLogoSrc.indexOf(';');
      var filetype = customLogoSrc.substring(filetypeBeginIdx, filetypeEndIdx);

      var base64 = customLogoSrc.substring(customLogoSrc.indexOf(',') + 1);

      return {
        isCustom: true,
        type: filetype,
        logo: base64
      };
    }

    var teamLogo = $('.fb-slider .active .icon--badge use').attr('xlink:href').replace('#icon--badge-', '');
    return {
      isCustom: false,
      type: null,
      logo: teamLogo
    };
  } catch (err) {
    teamLogoFormError();
    return {
      isCustom: null,
      type: null,
      logo: null,
      error: err
    };
  }
}

function verifyEmail(context) {
  if (context === 'password_reset_request') {
    var email = String($('.fb-form input[name="email"]')[0].value);
    if (email.length === 0) {
      emailFormError();
      return false;
    } else {
      return email;
    }
  }
}

function verifyResetPassword() {
  var teamPassword = $('.fb-form input[name="password"]')[0].value;
  if (teamPassword.length === 0) {
    passwordResetFormError('length');
    return false;
  } else {
    var confirm_password = $('.fb-form input[name="confirm_password"]')[0].value;
    if (teamPassword != confirm_password) {
      passwordResetFormError('notmatch');
      return false;
    } else {
      return teamPassword;
    }
  }
}

function goToPage(page) {
  window.location.href = '/index.php?p=' + page;
}

function sendIndexRequest(request_data) {
  $.post(
    'index.php?p=index&ajax=true',
    request_data
  ).fail(function() {
    // TODO: Make this a modal
    console.log('ERROR');
  }).done(function(data) {
    var responseData = JSON.parse(data);
    if (responseData.result === 'OK') {
      console.log('OK:' + responseData.message);
      goToPage(responseData.redirect);
    } else {
      // TODO: Make this a modal
      if (responseData.message === 'Password too simple') {
        teamPasswordFormError('toosimple');
      }
      if (responseData.message === 'Login failed') {
        teamLoginFormError();
      }
      if (responseData.message ===  'Login closed') {
        window.location.replace("/index.php?page=countdown");
      }
      if (responseData.message === 'Token failed') {
        teamTokenFormError();
      }
      if (responseData.message === 'Registration failed') {
        teamNameFormError();
      }
      if (responseData.message === 'Password reset request failed') {
        emailFormError();
      }
      if (responseData.message === 'Password reset failed') {
        passwordResetFormError('tokenerror');
      }
    }
  });
}

module.exports = {
  registerTeam: function() {
    var name = verifyTeamName('register');
    var password = verifyTeamPassword();
    var logoInfo: {isCustom: boolean, type: string, logo: string, error?: any} = verifyTeamLogo();
    var token = '';
    if ($('.fb-form input[name="token"]').length > 0) {
      token = $('.fb-form input[name="token"]')[0].value;
    }

    if (name && password && !logoInfo.error) {
      var register_data = {
        action: 'register_team',
        team_name: name,
        password: password,
        logo: logoInfo.logo,
        isCustomLogo: logoInfo.isCustom,
        logoType: logoInfo.type,
        token: token
      };
      sendIndexRequest(register_data);
    }
  },

  registerNames: function() {
    var name = verifyTeamName('register');
    var password = verifyTeamPassword();
    var logoInfo: {isCustom: boolean, type: string, logo: string, error?: any} = verifyTeamLogo();
    var token = '';
    if ($('.fb-form input[name="token"]').length > 0) {
      token = $('.fb-form input[name="token"]')[0].value;
    }
    var fields = $('.fb-form input[name^="registration_name_"]');
    var names = [];
    $.each(fields, function(index, nameField) {
      names.push(nameField.value);
    });
    var emails = [];
    fields = $('.fb-form input[name^="registration_email_"]');
    $.each(fields, function(index, nameField) {
      emails.push(nameField.value);
    });

    if (name && password && !logoInfo.error) {
      var register_data = {
        action: 'register_names',
        team_name: name,
        password: password,
        logo: logoInfo.logo,
        isCustomLogo: logoInfo.isCustom,
        logoType: logoInfo.type,
        token: token,
        names: JSON.stringify(names),
        emails: JSON.stringify(emails)
      };
      sendIndexRequest(register_data);
    }
  },

  loginTeam: function() {
    var loginSelect = $('.fb-form input[name="login_select"]')[0].value;
    var team, password, teamParam;

    if (loginSelect === 'on') {
      team = verifyTeamName('login');
      teamParam = 'team_id';
    } else {
      team = $('.fb-form input[name="team_name"]')[0].value;
      teamParam = 'team_name';
    }
    password = verifyTeamPassword();

    if (team && password) {
      var login_data = {
        action: 'login_team',
        password: password
      };
      login_data[teamParam] = team;
      sendIndexRequest(login_data);
    }
  },

  loginError: function() {
    $('.fb-form')[0].classList.add('form-error');
  },

  passwordResetRequest: function() {
    var email = verifyEmail('password_reset_request');

    if (email) {
      var request_data = {
        action: 'password_reset_request',
        email: email
      };
      sendIndexRequest(request_data);
    }
  },

  passwordReset: function() {
    var url = new URL(window.location.href);
    var token = url.searchParams.get("token");

    var password = verifyResetPassword();
    if (password) {
      var request_data = {
        action: 'password_reset',
        password: password,
        token: token
      };
      sendIndexRequest(request_data);
    }
  }
};
