# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_pam_wheel_group_for_su='sugroup'


if ! grep -q "^${var_pam_wheel_group_for_su}:[^:]*:[^:]*:[^:]*" /etc/group; then
    groupadd ${var_pam_wheel_group_for_su}
fi

# group must be empty
gpasswd -M '' ${var_pam_wheel_group_for_su}

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi