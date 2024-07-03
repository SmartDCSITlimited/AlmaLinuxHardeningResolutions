#!/bin/bash

# Check if a directory path argument is provided
if [ $# -ne 1 ]; then
    echo "Usage: $0 <directory>"
    exit 1
fi

directory="$1"

# Check if the directory exists
if [ ! -d "$directory" ]; then
    echo "Error: Directory '$directory' not found."
    exit 1
fi

# List of scripts to run (assuming they are in the specified directory)
scripts=(
    "content_rule_account_disable_post_pw_expiration.sh"
    "content_rule_account_password_pam_faillock_password_auth.sh"
    "content_rule_account_password_pam_faillock_system_auth.sh"
    "content_rule_accounts_maximum_age_login_defs.sh"
    "content_rule_accounts_minimum_age_login_defs.sh"
    "content_rule_accounts_password_pam_minclass.sh"
    "content_rule_accounts_password_pam_minlen.sh"
    "content_rule_accounts_password_pam_pwhistory_remember_password_auth.sh"
    "content_rule_accounts_password_pam_pwhistory_remember_system_auth.sh"
    "content_rule_accounts_passwords_pam_faillock_deny.sh"
    "content_rule_accounts_passwords_pam_faillock_unlock_time.sh"
    "content_rule_accounts_umask_etc_bashrc.sh"
    "content_rule_accounts_umask_etc_login_defs.sh"
    "content_rule_accounts_umask_etc_profile.sh"
    "content_rule_coredump_disable_backtraces.sh"
    "content_rule_coredump_disable_storage.sh"
    "content_rule_enable_authselect.sh"
    "content_rule_ensure_pam_wheel_group_empty.sh"
    "content_rule_use_pam_wheel_group_for_su.sh"
)

# Array to hold the names of failing scripts
failures=()

# Function to run scripts
run_scripts() {
    for script in "${scripts[@]}"; do
        full_script_path="$directory/$script"
        echo "Running $full_script_path..."
        output=$(bash "$full_script_path" 2>&1)
        if echo "$output" | grep -q "Remediation is not applicable, nothing was done"; then
            echo "$script failed: Remediation is not applicable, nothing was done."
            failures+=("$script")
        elif [ $? -ne 0 ]; then
            echo "$script failed."
            failures+=("$script")
        else
            echo "$script ran successfully."
        fi
    done
}

# Function to check SSSD configuration and status
check_sssd() {
    # Check if SSSD configuration files exist
    if [ -f /etc/sssd/sssd.conf ] || [ -f /etc/sssd/sssd.d/*.conf ]; then
        echo "SSSD configuration files found."
    else
        echo "Error: SSSD configuration files not found."
        return 1
    fi

    # Check if SSSD service is enabled and running
    if command -v systemctl >/dev/null && systemctl is-enabled sssd.service >/dev/null; then
        echo "SSSD service is enabled."
        if systemctl is-active sssd.service >/dev/null; then
            echo "SSSD service is running."
        else
            echo "Error: SSSD service is not running."
            return 1
        fi
    else
        echo "Error: SSSD service is not enabled."
        return 1
    fi

    return 0
}

# Run the scripts
run_scripts

# Check SSSD after running scripts
echo "Checking SSSD configuration..."
check_sssd
sssd_status=$?

# Report failing scripts
if [ ${#failures[@]} -eq 0 ]; then
    echo "All scripts ran successfully."
else
    echo "The following scripts failed:"
    for failed_script in "${failures[@]}"; do
        echo "$failed_script"
    done
fi

# Exit with appropriate status
if [ ${#failures[@]} -eq 0 ] && [ $sssd_status -eq 0 ]; then
    exit 0
else
    exit 1
fi
