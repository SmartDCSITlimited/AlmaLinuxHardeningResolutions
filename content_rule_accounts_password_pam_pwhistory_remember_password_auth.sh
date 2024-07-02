# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_password_pam_remember='5'
var_password_pam_remember_control_flag='requisite,required'


var_password_pam_remember_control_flag="$(echo $var_password_pam_remember_control_flag | cut -d \, -f 1)"

if [ -f /usr/bin/authselect ]; then
    if authselect list-features minimal | grep -q with-pwhistory; then
        if ! authselect check; then
        echo "
        authselect integrity check failed. Remediation aborted!
        This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
        It is not recommended to manually edit the PAM files when authselect tool is available.
        In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
        exit 1
        fi
        authselect enable-feature with-pwhistory

        authselect apply-changes -b
    else

        if ! authselect check; then
        echo "
        authselect integrity check failed. Remediation aborted!
        This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
        It is not recommended to manually edit the PAM files when authselect tool is available.
        In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
        exit 1
        fi

        CURRENT_PROFILE=$(authselect current -r | awk '{ print $1 }')
        # If not already in use, a custom profile is created preserving the enabled features.
        if [[ ! $CURRENT_PROFILE == custom/* ]]; then
            ENABLED_FEATURES=$(authselect current | tail -n+3 | awk '{ print $2 }')
            authselect create-profile hardening -b $CURRENT_PROFILE
            CURRENT_PROFILE="custom/hardening"

            authselect apply-changes -b --backup=before-hardening-custom-profile
            authselect select $CURRENT_PROFILE
            for feature in $ENABLED_FEATURES; do
                authselect enable-feature $feature;
            done

            authselect apply-changes -b --backup=after-hardening-custom-profile
        fi
        PAM_FILE_NAME=$(basename "/etc/pam.d/password-auth")
        PAM_FILE_PATH="/etc/authselect/$CURRENT_PROFILE/$PAM_FILE_NAME"

        authselect apply-changes -b
        if ! grep -qP '^\s*password\s+'"$var_password_pam_remember_control_flag"'\s+pam_pwhistory.so\s*.*' "$PAM_FILE_PATH"; then
            # Line matching group + control + module was not found. Check group + module.
            if [ "$(grep -cP '^\s*password\s+.*\s+pam_pwhistory.so\s*' "$PAM_FILE_PATH")" -eq 1 ]; then
                # The control is updated only if one single line matches.
                sed -i -E --follow-symlinks 's/^(\s*password\s+).*(\bpam_pwhistory.so.*)/\1'"$var_password_pam_remember_control_flag"' \2/' "$PAM_FILE_PATH"
            else
                LAST_MATCH_LINE=$(grep -nP "^password.*requisite.*pam_pwquality\.so" "$PAM_FILE_PATH" | tail -n 1 | cut -d: -f 1)
                if [ ! -z $LAST_MATCH_LINE ]; then
                    sed -i --follow-symlinks $LAST_MATCH_LINE' a password     '"$var_password_pam_remember_control_flag"'    pam_pwhistory.so' "$PAM_FILE_PATH"
                else
                    echo 'password    '"$var_password_pam_remember_control_flag"'    pam_pwhistory.so' >> "$PAM_FILE_PATH"
                fi
            fi
        fi
    fi
else
    if ! grep -qP '^\s*password\s+'"$var_password_pam_remember_control_flag"'\s+pam_pwhistory.so\s*.*' "/etc/pam.d/password-auth"; then
        # Line matching group + control + module was not found. Check group + module.
        if [ "$(grep -cP '^\s*password\s+.*\s+pam_pwhistory.so\s*' "/etc/pam.d/password-auth")" -eq 1 ]; then
            # The control is updated only if one single line matches.
            sed -i -E --follow-symlinks 's/^(\s*password\s+).*(\bpam_pwhistory.so.*)/\1'"$var_password_pam_remember_control_flag"' \2/' "/etc/pam.d/password-auth"
        else
            LAST_MATCH_LINE=$(grep -nP "^password.*requisite.*pam_pwquality\.so" "/etc/pam.d/password-auth" | tail -n 1 | cut -d: -f 1)
            if [ ! -z $LAST_MATCH_LINE ]; then
                sed -i --follow-symlinks $LAST_MATCH_LINE' a password     '"$var_password_pam_remember_control_flag"'    pam_pwhistory.so' "/etc/pam.d/password-auth"
            else
                echo 'password    '"$var_password_pam_remember_control_flag"'    pam_pwhistory.so' >> "/etc/pam.d/password-auth"
            fi
        fi
    fi
fi

PWHISTORY_CONF="/etc/security/pwhistory.conf"
if [ -f $PWHISTORY_CONF ]; then
    regex="^\s*remember\s*="
    line="remember = $var_password_pam_remember"
    if ! grep -q $regex $PWHISTORY_CONF; then
        echo $line >> $PWHISTORY_CONF
    else
        sed -i --follow-symlinks 's|^\s*\(remember\s*=\s*\)\(\S\+\)|\1'"$var_password_pam_remember"'|g' $PWHISTORY_CONF
    fi
    if [ -e "/etc/pam.d/password-auth" ] ; then
        PAM_FILE_PATH="/etc/pam.d/password-auth"
        if [ -f /usr/bin/authselect ]; then

            if ! authselect check; then
            echo "
            authselect integrity check failed. Remediation aborted!
            This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
            It is not recommended to manually edit the PAM files when authselect tool is available.
            In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
            exit 1
            fi

            CURRENT_PROFILE=$(authselect current -r | awk '{ print $1 }')
            # If not already in use, a custom profile is created preserving the enabled features.
            if [[ ! $CURRENT_PROFILE == custom/* ]]; then
                ENABLED_FEATURES=$(authselect current | tail -n+3 | awk '{ print $2 }')
                authselect create-profile hardening -b $CURRENT_PROFILE
                CURRENT_PROFILE="custom/hardening"

                authselect apply-changes -b --backup=before-hardening-custom-profile
                authselect select $CURRENT_PROFILE
                for feature in $ENABLED_FEATURES; do
                    authselect enable-feature $feature;
                done

                authselect apply-changes -b --backup=after-hardening-custom-profile
            fi
            PAM_FILE_NAME=$(basename "/etc/pam.d/password-auth")
            PAM_FILE_PATH="/etc/authselect/$CURRENT_PROFILE/$PAM_FILE_NAME"

            authselect apply-changes -b
        fi

    if grep -qP '^\s*password\s.*\bpam_pwhistory.so\s.*\bremember\b' "$PAM_FILE_PATH"; then
        sed -i -E --follow-symlinks 's/(.*password.*pam_pwhistory.so.*)\bremember\b=?[[:alnum:]]*(.*)/\1\2/g' "$PAM_FILE_PATH"
    fi
        if [ -f /usr/bin/authselect ]; then

            authselect apply-changes -b
        fi
    else
        echo "/etc/pam.d/password-auth was not found" >&2
    fi
else
    PAM_FILE_PATH="/etc/pam.d/password-auth"
    if [ -f /usr/bin/authselect ]; then

        if ! authselect check; then
        echo "
        authselect integrity check failed. Remediation aborted!
        This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
        It is not recommended to manually edit the PAM files when authselect tool is available.
        In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
        exit 1
        fi

        CURRENT_PROFILE=$(authselect current -r | awk '{ print $1 }')
        # If not already in use, a custom profile is created preserving the enabled features.
        if [[ ! $CURRENT_PROFILE == custom/* ]]; then
            ENABLED_FEATURES=$(authselect current | tail -n+3 | awk '{ print $2 }')
            authselect create-profile hardening -b $CURRENT_PROFILE
            CURRENT_PROFILE="custom/hardening"

            authselect apply-changes -b --backup=before-hardening-custom-profile
            authselect select $CURRENT_PROFILE
            for feature in $ENABLED_FEATURES; do
                authselect enable-feature $feature;
            done

            authselect apply-changes -b --backup=after-hardening-custom-profile
        fi
        PAM_FILE_NAME=$(basename "/etc/pam.d/password-auth")
        PAM_FILE_PATH="/etc/authselect/$CURRENT_PROFILE/$PAM_FILE_NAME"

        authselect apply-changes -b
    fi
    if ! grep -qP '^\s*password\s+'"requisite"'\s+pam_pwhistory.so\s*.*' "$PAM_FILE_PATH"; then
        # Line matching group + control + module was not found. Check group + module.
        if [ "$(grep -cP '^\s*password\s+.*\s+pam_pwhistory.so\s*' "$PAM_FILE_PATH")" -eq 1 ]; then
            # The control is updated only if one single line matches.
            sed -i -E --follow-symlinks 's/^(\s*password\s+).*(\bpam_pwhistory.so.*)/\1'"requisite"' \2/' "$PAM_FILE_PATH"
        else
            echo 'password    '"requisite"'    pam_pwhistory.so' >> "$PAM_FILE_PATH"
        fi
    fi
    # Check the option
    if ! grep -qP '^\s*password\s+'"requisite"'\s+pam_pwhistory.so\s*.*\sremember\b' "$PAM_FILE_PATH"; then
        sed -i -E --follow-symlinks '/\s*password\s+'"requisite"'\s+pam_pwhistory.so.*/ s/$/ remember='"$var_password_pam_remember"'/' "$PAM_FILE_PATH"
    else
        sed -i -E --follow-symlinks 's/(\s*password\s+'"requisite"'\s+pam_pwhistory.so\s+.*)('"remember"'=)[[:alnum:]]+\s*(.*)/\1\2'"$var_password_pam_remember"' \3/' "$PAM_FILE_PATH"
    fi
    if [ -f /usr/bin/authselect ]; then

        authselect apply-changes -b
    fi
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi