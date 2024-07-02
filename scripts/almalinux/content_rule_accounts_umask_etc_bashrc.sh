# Remediation is applicable only in certain platforms
if rpm --quiet -q bash; then

var_accounts_user_umask='027'






grep -q "^[^#]*\bumask" etc/bashrc && \
  sed -i -E -e "s/^([^#]*\bumask).*/\1 $var_accounts_user_umask/g" etc/bashrc
if ! [ $? -eq 0 ]; then
    echo "umask $var_accounts_user_umask" >> etc/bashrc
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi