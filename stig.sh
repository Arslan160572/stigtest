#!/bin/bash
function Backup () {
    echo
    echo "Backing up current configuration files."

    if [ ! -d "$BackupDIR" ]
    then
        mkdir "$BackupDIR"
    fi

    cp /etc/yum.conf "$BackupDIR"/yum.conf.old
    cp /etc/sysctl.conf "$BackupDIR"/sysctl.conf.old
    authconfig --savebackup="$BackupDIR"/authbackup
}

#Restore backups
function Restore () {
    echo
    echo "Restoring previous file backups"

    if [ -d "$BackupDIR" ]
    then
        authconfig --restorebackup="$BackupDIR"
        cp "$BackupDIR"/yum.conf.old /etc/yum.conf
        cp "$BackupDIR"/audit/rules.d/audit.rules.old /etc/audit/rules.d/audit.rules
        cp "$BackupDIR"/sysctl.conf.old /etc/sysctl.conf
        authconfig --restorebackup="$BackupDIR"/authbackup
    fi
}

#--------------------------------------------
#STIGS
#STIGs for Red Hat 7, Version 2 Release 3.
#--------------------------------------------

#--------------
#CAT III\Low
#--------------

#Set yum to remove unneeded packages, V-71987
function V71987 () {
    local Regex1="^(\s*)#clean_requirements_on_remove=\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)#clean_requirements_on_remove=\S+(\s*#.*)?\s*$/\nclean_requirements_on_remove=1\2/"
    local Regex3="^(\s*)clean_requirements_on_remove=\S+(\s*#.*)?\s*$"
    local Regex4="s/^(\s*)clean_requirements_on_remove=\S+(\s*#.*)?\s*$/\nclean_requirements_on_remove=1\2/"
    local Regex5="^(\s*)clean_requirements_on_remove=1?\s*$"
    local Success="Yum set to remove unneeded packages, per V-71987."
    local Failure="Failed to set yum to remove unneeded packages, not in compliance V-71987."

    echo
    ( (grep -E -q "$Regex1" /etc/yum.conf && sed -ri "$Regex2" /etc/yum.conf) || (grep -E -q "$Regex3" /etc/yum.conf && sed -ri "$Regex4" /etc/yum.conf) ) || echo "clean_requirements_on_remove=1" >> /etc/yum.conf
    (grep -E -q "$Regex5" /etc/yum.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Verify system is using tmp mount service, V-72065
#function V72065 () {
 #   local Regex1="^(\s*)enabled\s*$"
 #   local Success="System is set to create a separate file system for /tmp, per V-72065."
 #   local Failure="Failed to set system to create a separate file system for /tmp, not in compliance V-72065."

 #   echo
 #   systemctl enable tmp.mount > /dev/null
 #   (systemctl is-enabled tmp.mount | grep -E -q "$Regex1" && echo "$Success") || { echo "$Failure" ; exit 1; }
#}

#Set mx concurrent sessions to 10, V-72217
#function V72217 () {
#    local Regex1="^(\s*)#*\s*hard\s*maxlogins\s+\S+(\s*#.*)?\s*$"
#    local Regex2="s/^(\s*)#*\s*hard\s*maxlogins\s+\S+(\s*#.*)?\s*$/\* hard maxlogins 10\2/"
#    local Regex3="^(\s*)\*\s*hard\s*maxlogins\s+\S+(\s*#.*)?\s*$"
#    local Regex4="s/^(\s*)\*\s*hard\s*maxlogins\s+\S+(\s*#.*)?\s*$/\* hard maxlogins 10\2/"
#    local Regex5="^(\s*)\*\s*hard\s*maxlogins\s*10?\s*$"
#    local Success="Set max concurrent sessions to 10, per V-72217."
#    local Failure="Failed to set max concurrent sessions to 10, not in compliance V-72217."

#    echo
#    ( (grep -E -q "$Regex1" /etc/security/limits.conf && sed -ri "$Regex2" /etc/security/limits.conf) || (grep -E -q "$Regex3" /etc/security/limits.conf && sed -ri "$Regex4" /etc/security/limits.conf) ) || echo "* hard maxlogins 10" >> /etc/security/limits.conf
#    (grep -E -q "$Regex5" /etc/security/limits.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
#}

##Apply all compatible CATIII
function Low () {
    echo
    echo "Applying all compatible CAT IIIs"
    V71987
    #V72065, disabled currently due to causing issues with EC2IB
    V72217
}

#--------------
#CAT II\Medium
#--------------

#Set 15 min timeout period, V-71899
function V71899 () {
    local Regex1="^(\s*)#idle-activation-enabled=\S+?\s*$"
    local Regex2="s/^(\s*)#idle-activation-enabled=\S+(\s*#.*)?\s*$/\idle-activation-enabled=true\2/"
    local Regex3="^(\s*)idle-activation-enabled=\S+?\s*$"
    local Regex4="s/^(\s*)idle-activation-enabled=\S+(\s*#.*)?\s*$/\idle-activation-enabled=true\2/"
    local Regex5="^(\s*)idle-activation-enabled=true\s*$"
    local Success="15 min timeout for the screen saver is set, per V-71899."
    local Failure="15 min timeout for the screen saver has not been set, not in compliance with V-71899."

    echo
    if [ -f "/etc/dconf/db/local.d/00-screensaver" ]
    then
        ( (grep -E -q "$Regex1" /etc/dconf/db/local.d/00-screensaver && sed -ri "$Regex2" /etc/dconf/db/local.d/00-screensaver) || (grep -E -q "$Regex3" /etc/dconf/db/local.d/00-screensaver && sed -ri "$Regex4" /etc/dconf/db/local.d/00-screensaver) ) ||echo "idle-activation-enabled=true" >> /etc/dconf/db/local.d/00-screensaver
    else
        mkdir -p /etc/dconf/db/local.d/
        echo "idle-activation-enabled=true" >> /etc/dconf/db/local.d/00-screensaver
    fi
    (grep -E -q "$Regex5" /etc/dconf/db/local.d/00-screensaver && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set passwords to require a number of uppercase characters, V-71903
function V71903 () {
    local Regex1="^(\s*)ucredit\s*=\s*-1\s*$"
    local Success="Password is set to require a number of uppercase characters, per V-71903"
    local Failure="Password isn't set to require a number of uppercase characters, not in compliance with V-71903."

    echo
    authconfig --enablerequpper --update
    (grep -E -q "$Regex1" /etc/security/pwquality.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set password to require a number of lowercase characters, V-71905
function V71905 () {
    local Regex1="^(\s*)lcredit\s*=\s*-1\s*$"
    local Success="Password is set to require a number of lowercase characters, per V-71905"
    local Failure="Password isn't set to require a number of lowercase characters, not in compliance with V-71905."

    echo
    authconfig --enablereqlower --update
    (grep -E -q "$Regex1" /etc/security/pwquality.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set password to require a number of numerical characters, V-71907
function V71907 () {
    local Regex1="^(\s*)dcredit\s*=\s*-1\s*$"
    local Success="Password is set to require a number of numerical characters, per V-71907"
    local Failure="Password isn't set to require a number of numerical characters, not in compliance with V-71907."

    echo
    authconfig --enablereqdigit --update
    (grep -E -q "$Regex1" /etc/security/pwquality.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set password to require a number of special characters, V-71909
function V71909 () {
    local Regex1="^(\s*)ocredit\s*=\s*-1\s*$"
    local Success="Password is set to require a number of special characters, per V-71909"
    local Failure="Password isn't set to require a number of special characters, not in compliance with V-71909."

    echo
    authconfig --enablereqother --update
    (grep -E -q "$Regex1" /etc/security/pwquality.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set min number of characters changed from old password, V-71911
function V71911 () {
    local Regex1="^(\s*)#\s*difok\s*=\s*\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)#\s*difok\s*=\s*\S+(\s*#.*)?\s*$/\difok = 8\2/"
    local Regex3="^(\s*)difok\s*=\s*\S+(\s*#.*)?\s*$"
    local Regex4="s/^(\s*)difok\s*=\s*\S+(\s*#.*)?\s*$/\difok = 8\2/"
    local Regex5="^(\s*)difok\s*=\s*8\s*$"
    local Success="Set so a min number of 8 characters are changed from the old password, per V-71911"
    local Failure="Failed to set the password to use a min number of 8 characters are changed from the old password, not in compliance with V-71911"

    echo
    ( (grep -E -q "$Regex1" /etc/security/pwquality.conf && sed -ri "$Regex2" /etc/security/pwquality.conf) || (grep -E -q "$Regex3" /etc/security/pwquality.conf && sed -ri "$Regex4" /etc/security/pwquality.conf) ) || echo "difok = 8" >> /etc/security/pwquality.conf
    (grep -E -q "$Regex5" /etc/security/pwquality.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set min required classes of characters for a new password, V-71913
function V71913 () {
    local Regex1="^(\s*)minclass\s*=\s*4\s*$"
    local Success="Password set to use a min number of 4 character classes in a new password, per V-71913."
    local Failure="Failed to set password to use a min number of 4 character classes in a new password, not in compliance with V-71913."

    echo
    authconfig --passminclass=4 --update
    (grep -E -q "$Regex1" /etc/security/pwquality.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set max number of characters that can repeat, V-71915
function V71915 () {
    local Regex1="^(\s*)maxrepeat\s*=\s*3\s*$"
    local Success="Passwords are set to only allow 3 repeat characters in a new password, per V-71915."
    local Failure="Failed to set passwords to only allow 3 repeat characters in a new password, not in compliance with V-71915."

    echo
    authconfig --passmaxrepeat=3 --update
    (grep -E -q "$Regex1" /etc/security/pwquality.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set max number of characters of the same class that can repeat, V-71917
function V71917 () {
    local Regex1="^(\s*)maxclassrepeat\s*=\s*4\s*$"
    local Success="Passwords are set to only allow 4 characters of the same class to repeat in a new password, per V-71917."
    local Failure="Failed to set passwords only allow 4 repeat characters of the same class in a new password, not in compliance with V-71917."

    echo
    authconfig --passmaxclassrepeat=4 --update
    (grep -E -q "$Regex1" /etc/security/pwquality.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set passwords to use SHA512, V-71919
#function V71919 () {
#    local Regex1="password\s*hashing\s*algorithm\s*is\s*sha512\s*$"
#    local Success="Passwords are set to use SHA512 encryption, per V-71919."
#    local Failure="Failed to set passwords to use SHA512 encryption, not in compliance with V-71919."

#    echo
#    authconfig --passalgo=sha512 --update
#    (authconfig --test | grep -E -q "$Regex1" && echo "$Success") || { echo "$Failure" ; exit 1; }
#}

#Set system to create SHA512 hashed passwords, V-71921
#function V71921 () {
#    local Regex1="^(\s*)ENCRYPT_METHOD\s*SHA512\s*$"
#    local Success="Passwords are set to be created with SHA512 hash, per V-71921."
#    local Failure="Failed to set passwords to be created with SHA512 hash, not in compliance with V-71921."

#    echo
#    (grep -E -q "$Regex1" /etc/login.defs && echo "$Success") || { echo "$Failure" ; exit 1; }
#}

#Set password min lifetome to 1 day, V-71925
function V71925 () {
    local Regex1="^(\s*)PASS_MIN_DAYS\s+\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)PASS_MIN_DAYS\s+\S+(\s*#.*)?\s*$/\PASS_MIN_DAYS 1\2/"
    local Regex3="^(\s*)PASS_MIN_DAYS\s*1\s*$"
    local Success="Passwords are set to have a minimum lifetime of 1 day, per V-71925."
    local Failure="Failed to set passwords to have a minimum lifetime of 1 day, not in compliance with V-71925."

    echo
    (grep -E -q "$Regex1" /etc/login.defs && sed -ri "$Regex2" /etc/login.defs) || echo "PASS_MIN_DAYS 1" >> /etc/login.defs
    getent passwd | cut -d ':' -f 1 | xargs -n1 chage --mindays 1
    (grep -E -q "$Regex3" /etc/login.defs && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#'Set password max lifetime to 60 days, V-71929, disabled due to able to break some build automaiton.
#function V71929 () {
#    local Regex1="^(\s*)PASS_MAX_DAYS\s+\S+(\s*#.*)?\s*$"
#    local Regex2="s/^(\s*)PASS_MAX_DAYS\s+\S+(\s*#.*)?\s*$/\PASS_MAX_DAYS 60\2/"
#    local Regex3="^(\s*)PASS_MAX_DAYS\s*60\s*$"
#    local Success="Passwords are set to have a maximum lifetime to 60 days, per V-71929."
#    local Failure="Failed to set passwords to have a maximum lifetime to 60 days, not in compliance with V-71929."

#    echo
#    grep -E -q "$Regex1" /etc/login.defs && sed -ri "$Regex2" /etc/login.defs || echo "PASS_MAX_DAYS 60" >> /etc/login.defs
#    getent passwd | cut -d ':' -f 1 | xargs -n1 chage --maxdays 60
#    grep -E -q "$Regex3" /etc/login.defs && echo "$Success" || { echo "$Failure" ; exit 1; }
#}'

#Limit password reuse to 5, V-71933
#function V71933 () {
#    local Regex1="^\s*password\s*\s*\s*\s*requisite\s*\s*\s*\s*\s*pam_pwhistory.so\s*use_authtok\s*remember=\S+(\s*#.*)?(\s+.*)$"
#    local Regex2="s/^(\s*)password\s*\s*\s*\s*requisite\s*\s*\s*\s*\s*pam_pwhistory.so\s*use_authtok\s*remember=\S+(\s*#.*)\s*retry=\S+(\s*#.*)?\s*S/\password\s*\s*\s*\s*requisite\s*\s*\s*\s*\s*tpam_pwhistory.so\s*use_authtok\s*remember=5\s*retry=3\2/"
#    local Regex3="^(\s*)password\s*\s*\s*\s*requisite\s*\s*\s*\s*\s*pam_pwhistory.so\s*use_authtok\s*remember=5\s*retry=3\s*$"
#    local Success="System is set to keep password history of the last 5 passwords, per V-71933."
#    local Failure="Failed to set system to keep password history of the last 5 passwords, not in compliance with V-71933."

#    echo
#    (grep -E -q "$Regex1" /etc/pam.d/system-auth && sed -ri  "$Regex2" /etc/pam.d/system-auth) || echo "password    requisite     pam_pwhistory.so use_authtok remember=5 retry=3" >> /etc/pam.d/system-auth
#    (grep -E -q "$Regex1" /etc/pam.d/password-auth && sed -ri  "$Regex2" /etc/pam.d/password-auth) || echo "password    requisite     pam_pwhistory.so use_authtok remember=5 retry=3" >> /etc/pam.d/password-auth
#    ( (grep -E -q "$Regex3" /etc/pam.d/password-auth && grep -E -q "$Regex3" /etc/pam.d/system-auth) && echo "$Success") || { echo "$Failure" ; exit 1; }
#}

#Set min 15 character password length, V-71935
function V71935 () {
    local Regex1="^(\s*)minlen\s*=\s*15\s*$"
    local Success="Passwords are set to have a min of 15 characters, per V-71935."
    local Failure="Failed to set passwords to use a min of 15 characters, not in compliance with V-71935."

    echo
    authconfig --passminlen=15 --update
    (grep -E -q "$Regex1" /etc/security/pwquality.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Disable account identifiers, V-71941
function V71941 () {
    local Regex1="^(\s*)INACTIVE=\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)INACTIVE=\S+(\s*#.*)?\s*$/\INACTIVE=0\2/"
    local Regex3="^(\s*)INACTIVE=0\s*$"
    local Success="Account identifiers are disabled once the password expires, per V-71941."
    local Failure="Failed to set account identifiers are disabled once the password expires, not in compliance with V-71941."

    echo
    (grep -E -q "$Regex1" /etc/default/useradd && sed -ri "$Regex2" /etc/default/useradd) || echo "INACTIVE=0" >> /etc/default/useradd
    (grep -E -q "$Regex3" /etc/default/useradd && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set system to lock account after 3 failed logon attempts within 15 mins, V-71943
function V71943 () {
    local Regex1="(\s*)fail_interval=900\s*unlock_time=900\s*"
    local Success="Account lockout time after 3 failed logon attempts set to 15 mins, per V-71943."
    local Failure="Failed to set account lockout time after 3 failed logon attempts set to 15 mins, not in compliance with V-71943."

    echo
    authconfig --enablefaillock --update
    (authconfig --test | grep -q 'even_deny_root' && authconfig --faillock "audit deny=3 even_deny_root fail_interval=900 unlock_time=900" --update) || authconfig --faillock "audit deny=3 fail_interval=900 unlock_time=900" --update
    (authconfig --test | grep -E -q "$Regex1" && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set sysetm to even lock the root account, V-71945
function V71945 () {
    local Regex1="(\s*)even_deny_root\s*fail_interval=900\s*unlock_time=900\s*"
    local Success="Account, including root, lockout time after 3 failed logon attempts set to 15 mins, per V-71943."
    local Failure="Failed to set account, including root, lockout time after 3 failed logon attempts set to 15 mins, not in compliance with V-71943."

    echo
    authconfig --enablefaillock --update
    authconfig --faillock "audit deny=3 even_deny_root fail_interval=900 unlock_time=900" --update
    (authconfig --test | grep -E -q "$Regex1" && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set delay between failed logon attenpts, V-71951
function V71951 () {
    local Regex1="^(\s*)FAIL_DELAY\s+\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)FAIL_DELAY\s+\S+(\s*#.*)?\s*$/\FAIL_DELAY 4\2/"
    local Regex3="^(\s*)FAIL_DELAY\s*4\s*$"
    local Success="Set a 4 sec delay between failed logon attempts, per V-71951."
    local Failure="Failed to set a 4 sec delay between failed logon attempts, not in compliance with V-71951."

    echo
    (grep -E -q "$Regex1" /etc/login.defs && sed -ri "$Regex2" /etc/login.defs) || echo "FAIL_DELAY 4" >> /etc/login.defs
    (grep -E -q "$Regex3" /etc/login.defs && echo "$Success") || { echo "$Failure" ; exit 1; }
}

# Set SSH HostbasedAuthentication to no, V-71959
#function V71959 () {
#    local Regex1="^(\s*)#HostbasedAuthentication\s+\S+(\s*#.*)?\s*$"
#    local Regex2="s/^(\s*)#HostbasedAuthentication\s+\S+(\s*#.*)?\s*$/\HostbasedAuthentication no\2/"
#    local Regex3="^(\s*)HostbasedAuthentication\s+\S+(\s*#.*)?\s*$"
#    local Regex4="s/^(\s*)HostbasedAuthentication\s+\S+(\s*#.*)?\s*$/\HostbasedAuthentication no\2/"
#    local Regex5="^(\s*)HostbasedAuthentication\s*no\s*$"
#    local Success="Set OS to not allow non-certificate trusted host SSH to log onto the system, per V-71959."
#    local Failure="Failed to set OS to not allow non-certificate trusted host SSH to log onto the system, not in compliance with V-71959."

#    echo
#    ( (grep -E -q "$Regex1" /etc/ssh/sshd_config && sed -ri "$Regex2" /etc/ssh/sshd_config) || (grep -E -q "$Regex3" /etc/ssh/sshd_config && sed -ri "$Regex4" /etc/ssh/sshd_config) )|| echo "HostbasedAuthentication no" >> /etc/ssh/sshd_config
#    (grep -E -q "$Regex5" /etc/ssh/sshd_config && echo "$Success") || { echo "$Failure" ; exit 1; }
#}

#Set audit of privileged functions, V-72095
function V72095 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+execve\s+-C\s+uid!=euid\s+-F\s+euid=0\s+-k\s+setuid\s*(#.*)?$"
    local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+execve\s+-C\s+uid!=euid\s+-F\s+euid=0\s+-k\s+setuid\s*(#.*)?$"
    local Regex3="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+execve\s+-C\s+gid!=egid\s+-F\s+egid=0\s+-k\s+setgid\s*(#.*)?$"
    local Regex4="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+execve\s+-C\s+gid!=egid\s+-F\s+egid=0\s+-k\s+setgid\s*(#.*)?$"
    local Success32="Auditing of privileged functions is enabled on 32bit systems, per V-72095."
    local Success64="Auditing of privileged functions is enabled on 64bit systems, per V-72095."
    local Failure32="Failed to set auditing of privileged functions on 32bit systems, not in compliance with V-72095."
    local Failure64="Failed to set auditing of privileged functions on 64bit systems, not in compliance with V-72095."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k setuid" >> /etc/audit/rules.d/audit.rules
    (uname -p | grep -q 'x86_64' && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k setuid" >> /etc/audit/rules.d/audit.rules
    grep -E -q "$Regex3" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -k setgid" >> /etc/audit/rules.d/audit.rules
    (uname -p | grep -q 'x86_64' && grep -E -q "$Regex4" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k setgid" >> /etc/audit/rules.d/audit.rules
    ( (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && grep -E -q "$Regex3" /etc/audit/rules.d/audit.rules) && echo "$Success32") || { echo "$Failure32" ; exit 1; }
    echo
    uname -p | grep -q 'x86_64' && ( ( (grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules && grep -E -q "$Regex4" /etc/audit/rules.d/audit.rules) && echo "$Success64") || { echo "$Failure64" ; exit 1; } )
}

#Set audit to audit of successful/unsuccessful attempts to use chown, V-72097
#function V72097 () {
#    local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+chown\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*(#.*)?$"
#    local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+chown\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*(#.*)?$"
#    local Success32="Auditing of successful/unsuccessful attempts to use chown is enabled on 32bit systems, per V-72097."
#    local Success64="Auditing of successful/unsuccessful attempts to use chown is enabled on 64bit systems, per V-72097."
#    local Failure32="Failed to set auditing of successful/unsuccessful attempts to use chown on 32bit systems, not in compliance with V-72097."
#    local Failure64="Failed to set auditing of successful/unsuccessful attempts to use chown on 64bit systems, not in compliance with V-72097."

#    echo
#    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S chown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
#    (uname -p | grep -q 'x86_64' && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S chown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
#    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success32") || { echo "$Failure32" ; exit 1; }
#    echo
#    uname -p | grep -q 'x86_64' && ( (grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules && echo "$Success64") || { echo "$Failure64" ; exit 1; } )
#}

#Set audit to audit of successful/unsuccessful attempts to use fchown, V-72099
#function V72099 () {
#    local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+fchown\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*(#.*)?$"
#    local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+fchown\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*(#.*)?$"
#    local Success32="Auditing of successful/unsuccessful attempts to use fchown is enabled on 32bit systems, per V-72099."
#    local Success64="Auditing of successful/unsuccessful attempts to use fchown is enabled on 64bit systems, per V-72099."
#    local Failure32="Failed to set auditing of successful/unsuccessful attempts to use fchown on 32bit systems, not in compliance with V-72099."
#    local Failure64="Failed to set auditing of successful/unsuccessful attempts to use fchown on 64bit systems, not in compliance with V-72099."

#    echo
#    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S fchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
#    (uname -p | grep -q 'x86_64' && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S fchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
#    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success32") || { echo "$Failure32" ; exit 1; }
#    echo
#    uname -p | grep -q 'x86_64' && ( (grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules && echo "$Success64") || { echo "$Failure64" ; exit 1; } )
#}

#Set audit to audit of successful/unsuccessful attempts to use lchown, V-72101
#function V72101 () {
 #   local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+lchown\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*(#.*)?$"
 #   local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+lchown\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*(#.*)?$"
 #   local Success32="Auditing of successful/unsuccessful attempts to use lchown is enabled on 32bit systems, per V-72101."
 #   local Success64="Auditing of successful/unsuccessful attempts to use lchown is enabled on 64bit systems, per V-72101."
 #   local Failure32="Failed to set auditing of successful/unsuccessful attempts to use lchown on 32bit systems, not in compliance with V-72101."
 #   local Failure64="Failed to set auditing of successful/unsuccessful attempts to use lchown on 64bit systems, not in compliance with V-72101."

 #   echo
 #   grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
 #   (uname -p | grep -q 'x86_64' && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
 #   (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success32") || { echo "$Failure32" ; exit 1; }
 #   echo
 #   uname -p | grep -q 'x86_64' && ( (grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules && echo "$Success64") || { echo "$Failure64" ; exit 1; } )
#}

#Set audit to audit of successful/unsuccessful attempts to use fchownat, V-72103
#function V72103 () {
 #   local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+fchownat\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*(#.*)?$"
 #   local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+fchownat\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*(#.*)?$"
 #   local Success32="Auditing of successful/unsuccessful attempts to use fchownat is enabled on 32bit systems, per V-72103."
 #   local Success64="Auditing of successful/unsuccessful attempts to use fchownat is enabled on 64bit systems, per V-72103."
 #   local Failure32="Failed to set auditing of successful/unsuccessful attempts to use fchownat on 32bit systems, not in compliance with V-72103."
 #   local Failure64="Failed to set auditing of successful/unsuccessful attempts to use fchownat on 64bit systems, not in compliance with V-72103."

 #   echo
 #   grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S fchownat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
 #   (uname -p | grep -q 'x86_64' && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S fchownat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
 #   (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success32") || { echo "$Failure32" ; exit 1; }
 #   echo
 #   uname -p | grep -q 'x86_64' && ( (grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules && echo "$Success64") || { echo "$Failure64" ; exit 1; } )
#}

#Set audit to audit of successful/unsuccessful attempts to use chmod, V-72105
#function V72105 () {
 #   local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+chmod\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*(#.*)?$"
 #   local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+chmod\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*(#.*)?$"
 #   local Success32="Auditing of successful/unsuccessful attempts to use chmod is enabled on 32bit systems, per V-72105."
 #   local Success64="Auditing of successful/unsuccessful attempts to use chmod is enabled on 64bit systems, per V-72105."
 #   local Failure32="Failed to set auditing of successful/unsuccessful attempts to use chmod on 32bit systems, not in compliance with V-72105."
 #   local Failure64="Failed to set auditing of successful/unsuccessful attempts to use chmod on 64bit systems, not in compliance with V-72105."

 #   echo
 #   grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S chmod -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
 #   (uname -p | grep -q 'x86_64' && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S chmod -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
 #   (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success32") || { echo "$Failure32" ; exit 1; }
 #   echo
 #   uname -p | grep -q 'x86_64' && ( (grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules && echo "$Success64") || { echo "$Failure64" ; exit 1; } )
#}

#Set audit to audit of successful/unsuccessful attempts to use fchmod, V-72107
#function V72107 () {
 #   local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+fchmod\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*(#.*)?$"
 #   local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+fchmod\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*(#.*)?$"
 #   local Success32="Auditing of successful/unsuccessful attempts to use fchmod is enabled on 32bit systems, per V-72107."
 #   local Success64="Auditing of successful/unsuccessful attempts to use fchmod is enabled on 64bit systems, per V-72107."
 #   local Failure32="Failed to set auditing of successful/unsuccessful attempts to use fchmod on 32bit systems, not in compliance with V-72107."
 #   local Failure64="Failed to set auditing of successful/unsuccessful attempts to use fchmod on 64bit systems, not in compliance with V-72107."

 #   echo
 #   grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S fchmod -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
 #   (uname -p | grep -q 'x86_64' && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S fchmod -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
 #   (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success32") || { echo "$Failure32" ; exit 1; }
 #   echo
 #   uname -p | grep -q 'x86_64' && ( (grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules && echo "$Success64") || { echo "$Failure64" ; exit 1; } )
#}

#Set audit to audit of successful/unsuccessful attempts to use fchmodat, V-72109
#function V72109 () {
 #   local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+fchmodat\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*(#.*)?$"
 #   local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+fchmodat\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*(#.*)?$"
 #   local Success32="Auditing of successful/unsuccessful attempts to use fchmodat is enabled on 32bit systems, per V-72109."
 #   local Success64="Auditing of successful/unsuccessful attempts to use fchmodat is enabled on 64bit systems, per V-72109."
 #   local Failure32="Failed to set auditing of successful/unsuccessful attempts to use fchmodat on 32bit systems, not in compliance with V-72109."
 #   local Failure64="Failed to set auditing of successful/unsuccessful attempts to use fchmodat on 64bit systems, not in compliance with V-72109."

 #   echo
 #   grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
 #   (uname -p | grep -q 'x86_64' && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
 #   (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success32") || { echo "$Failure32" ; exit 1; }
 #   echo
 #   uname -p | grep -q 'x86_64' && ( (grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules && echo "$Success64") || { echo "$Failure64" ; exit 1; } )
#}

#Set audit to audit of successful/unsuccessful attempts to use setxattr, V-72111
#function V72111 () {
 #   local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+setxattr\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*(#.*)?$"
 #   local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+setxattr\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*(#.*)?$"
 #   local Success32="Auditing of successful/unsuccessful attempts to use setxattr is enabled on 32bit systems, per V-72111."
 #   local Success64="Auditing of successful/unsuccessful attempts to use setxattr is enabled on 64bit systems, per V-72111."
 #   local Failure32="Failed to set auditing of successful/unsuccessful attempts to use setxattr on 32bit systems, not in compliance with V-72111."
 #   local Failure64="Failed to set auditing of successful/unsuccessful attempts to use setxattr on 64bit systems, not in compliance with V-72111."

 #   echo
 #   grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S setxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
 #   (uname -p | grep -q 'x86_64' && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S setxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
 #   (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success32") || { echo "$Failure32" ; exit 1; }
 #   echo
 #   uname -p | grep -q 'x86_64' && ( (grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules && echo "$Success64") || { echo "$Failure64" ; exit 1; } )
#}

#Set audit to audit of successful/unsuccessful attempts to use fsetxattr, V-72113
#function V72113 () {
 #   local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+fsetxattr\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*(#.*)?$"
 #   local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+fsetxattr\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*(#.*)?$"
 #   local Success32="Auditing of successful/unsuccessful attempts to use fsetxattr is enabled on 32bit systems, per V-72113."
 #   local Success64="Auditing of successful/unsuccessful attempts to use fsetxattr is enabled on 64bit systems, per V-72113."
 #   local Failure32="Failed to set auditing of successful/unsuccessful attempts to use fsetxattr on 32bit systems, not in compliance with V-72113."
 #   local Failure64="Failed to set auditing of successful/unsuccessful attempts to use fsetxattr on 64bit systems, not in compliance with V-72113."

 #   echo
 #   grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S fsetxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
 #   (uname -p | grep -q 'x86_64' && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S fsetxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
 #   (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success32") || { echo "$Failure32" ; exit 1; }
 #   echo
 #   uname -p | grep -q 'x86_64' && ( (grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules && echo "$Success64") || { echo "$Failure64" ; exit 1; } )
#}

#Set audit to audit of successful/unsuccessful attempts to use lsetxattr, V-72115
#function V72115 () {
 #   local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+lsetxattr\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*(#.*)?$"
 #   local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+lsetxattr\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*(#.*)?$"
 #   local Success32="Auditing of successful/unsuccessful attempts to use lsetxattr is enabled on 32bit systems, per V-72215."
 #   local Success64="Auditing of successful/unsuccessful attempts to use lsetxattr is enabled on 64bit systems, per V-72215."
 #   local Failure32="Failed to set auditing of successful/unsuccessful attempts to use lsetxattr on 32bit systems, not in compliance with V-72215."
 #   local Failure64="Failed to set auditing of successful/unsuccessful attempts to use lsetxattr on 64bit systems, not in compliance with V-72215."

 #   echo
 #   grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S lsetxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
 #   (uname -p | grep -q 'x86_64' && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S lsetxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
 #   (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success32") || { echo "$Failure32" ; exit 1; }
 #   echo
 #   uname -p | grep -q 'x86_64' && ( (grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules && echo "$Success64") || { echo "$Failure64" ; exit 1; } )
#}

#Set audit to audit of successful/unsuccessful attempts to use removexattr, V-72117
#function V72117 () {
 #   local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+removexattr\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*(#.*)?$"
 #   local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+removexattr\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*(#.*)?$"
 #   local Success32="Auditing of successful/unsuccessful attempts to use removexattr is enabled on 32bit systems, per V-72117."
 #   local Success64="Auditing of successful/unsuccessful attempts to use removexattr is enabled on 64bit systems, per V-72117."
 #   local Failure32="Failed to set auditing of successful/unsuccessful attempts to use removexattr on 32bit systems, not in compliance with V-72117."
 #   local Failure64="Failed to set auditing of successful/unsuccessful attempts to use removexattr on 64bit systems, not in compliance with V-72117."

 #   echo
 #   grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S removexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
 #   (uname -p | grep -q 'x86_64' && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S removexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
 #   (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success32") || { echo "$Failure32" ; exit 1; }
 #   echo
 #   uname -p | grep -q 'x86_64' && ( (grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules && echo "$Success64") || { echo "$Failure64" ; exit 1; } )
#}

#Set audit to audit of successful/unsuccessful attempts to use fremovexattr, V-72119
#function V72119 () {
 #   local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+fremovexattr\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*(#.*)?$"
 #   local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+fremovexattr\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*(#.*)?$"
 #   local Success32="Auditing of successful/unsuccessful attempts to use fremovexattr is enabled on 32bit systems, per V-72119."
 #   local Success64="Auditing of successful/unsuccessful attempts to use fremovexattr is enabled on 64bit systems, per V-72119."
 #   local Failure32="Failed to set auditing of successful/unsuccessful attempts to use fremovexattr on 32bit systems, not in compliance with V-72119."
 #   local Failure64="Failed to set auditing of successful/unsuccessful attempts to use fremovexattr on 64bit systems, not in compliance with V-72119."

 #   echo
 #   grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
 #   (uname -p | grep -q 'x86_64' && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
 #   (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success32") || { echo "$Failure32" ; exit 1; }
 #   echo
 #   uname -p | grep -q 'x86_64' && ( (grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules && echo "$Success64") || { echo "$Failure64" ; exit 1; } )
#}

#Set audit to audit of successful/unsuccessful attempts to use lremovexattr, V-72121
#function V72121 () {
 #   local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+lremovexattr\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*(#.*)?$"
 #   local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+lremovexattr\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*(#.*)?$"
 #   local Success32="Auditing of successful/unsuccessful attempts to use lremovexattr is enabled on 32bit systems, per V-72121."
 #   local Success64="Auditing of successful/unsuccessful attempts to use lremovexattr is enabled on 64bit systems, per V-72121."
 #   local Failure32="Failed to set auditing of successful/unsuccessful attempts to use lremovexattr on 32bit systems, not in compliance with V-72121."
 #   local Failure64="Failed to set auditing of successful/unsuccessful attempts to use lremovexattr on 64bit systems, not in compliance with V-72121."

 #   echo
 #   grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S lremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
 #   (uname -p | grep -q 'x86_64' && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S lremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
 #   (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success32") || { echo "$Failure32" ; exit 1; }
 #   echo
 #   uname -p | grep -q 'x86_64' && ( (grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules && echo "$Success64") || { echo "$Failure64" ; exit 1; } )
#}

#Set audit to audit of successful/unsuccessful attempts to use creat, V-72123
#function V72123 () {
 #   local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+creat\s+-F\s+exit=-EPERM\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*(#.*)?$"
 #   local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+creat\s+-F\s+exit=-EACCES\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*(#.*)?$"
 #   local Regex3="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+creat\s+-F\s+exit=-EPERM\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*(#.*)?$"
 #   local Regex4="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+creat\s+-F\s+exit=-EACCES\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*(#.*)?$"
 #   local Success32="Auditing of successful/unsuccessful attempts to use creat is enabled on 32bit systems, per V-72123."
 #   local Success64="Auditing of successful/unsuccessful attempts to use creat is enabled on 64bit systems, per V-72123."
 #   local Failure32="Failed to set auditing of successful/unsuccessful attempts to use creat on 32bit systems, not in compliance with V-72123."
 #   local Failure64="Failed to set auditing of successful/unsuccessful attempts to use creat on 64bit systems, not in compliance with V-72123."

  #  echo
  #  grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
  #  grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
  #  (uname -p | grep -q 'x86_64' && grep -E -q "$Regex3" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
  #  (uname -p | grep -q 'x86_64' && grep -E -q "$Regex4" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
  #  ( (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) && echo "$Success32") || { echo "$Failure32" ; exit 1; }
  #  echo
  #  uname -p | grep -q 'x86_64' && ( ( (grep -E -q "$Regex3" /etc/audit/rules.d/audit.rules && grep -E -q "$Regex4" /etc/audit/rules.d/audit.rules) && echo "$Success64") || { echo "$Failure64" ; exit 1; } )
#}

#Set audit to audit of successful/unsuccessful attempts to use open, V-72125
#function V72125 () {
 #   local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+open\s+-F\s+exit=-EPERM\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*(#.*)?$"
 #   local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+open\s+-F\s+exit=-EACCES\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*(#.*)?$"
 #   local Regex3="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+open\s+-F\s+exit=-EPERM\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*(#.*)?$"
 #   local Regex4="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+open\s+-F\s+exit=-EACCES\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*(#.*)?$"
 #   local Success32="Auditing of successful/unsuccessful attempts to use open is enabled on 32bit systems, per V-72125."
 #   local Success64="Auditing of successful/unsuccessful attempts to use open is enabled on 64bit systems, per V-72125."
 #   local Failure32="Failed to set auditing of successful/unsuccessful attempts to use open on 32bit systems, not in compliance with V-72125."
 #   local Failure64="Failed to set auditing of successful/unsuccessful attempts to use open on 64bit systems, not in compliance with V-72125."

 #   echo
 #   grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S open -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
 #   grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S open -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
 #   (uname -p | grep -q 'x86_64' && grep -E -q "$Regex3" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S open -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
 #   (uname -p | grep -q 'x86_64' && grep -E -q "$Regex4" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S open -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
 #   ( (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) && echo "$Success32") || { echo "$Failure32" ; exit 1; }
 #   echo
 #   uname -p | grep -q 'x86_64' && ( ( (grep -E -q "$Regex3" /etc/audit/rules.d/audit.rules && grep -E -q "$Regex4" /etc/audit/rules.d/audit.rules) && echo "$Success64") || { echo "$Failure64" ; exit 1; } )
#}

#Set audit to audit of successful/unsuccessful attempts to use openat, V-72127
#function V72127 () {
 #   local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+openat\s+-F\s+exit=-EPERM\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*(#.*)?$"
 #   local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+openat\s+-F\s+exit=-EACCES\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*(#.*)?$"
 #   local Regex3="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+openat\s+-F\s+exit=-EPERM\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*(#.*)?$"
 #   local Regex4="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+openat\s+-F\s+exit=-EACCES\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*(#.*)?$"
 #   local Success32="Auditing of successful/unsuccessful attempts to use openat is enabled on 32bit systems, per V-72127."
 #   local Success64="Auditing of successful/unsuccessful attempts to use openat is enabled on 64bit systems, per V-72127."
 #   local Failure32="Failed to set auditing of successful/unsuccessful attempts to use openat on 32bit systems, not in compliance with V-72127."
 #   local Failure64="Failed to set auditing of successful/unsuccessful attempts to use openat on 64bit systems, not in compliance with V-72127."

 #   echo
 #   grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S openat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
 #   grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S openat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
 #   (uname -p | grep -q 'x86_64' && grep -E -q "$Regex3" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S openat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
 #   (uname -p | grep -q 'x86_64' && grep -E -q "$Regex4" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S openat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
 #   ( (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) && echo "$Success32") || { echo "$Failure32" ; exit 1; }
 #   echo
 #   uname -p | grep -q 'x86_64' && ( ( (grep -E -q "$Regex3" /etc/audit/rules.d/audit.rules && grep -E -q "$Regex4" /etc/audit/rules.d/audit.rules) && echo "$Success64") || { echo "$Failure64" ; exit 1; } )
#}

#Set audit to audit of successful/unsuccessful attempts to use open_by_handle_at, V-72129
function V72129 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+open_by_handle_at\s+-F\s+exit=-EPERM\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*(#.*)?$"
    local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+open_by_handle_at\s+-F\s+exit=-EACCES\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*(#.*)?$"
    local Regex3="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+open_by_handle_at\s+-F\s+exit=-EPERM\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*(#.*)?$"
    local Regex4="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+open_by_handle_at\s+-F\s+exit=-EACCES\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*(#.*)?$"
    local Success32="Auditing of successful/unsuccessful attempts to use open_by_handle_at is enabled on 32bit systems, per V-72129."
    local Success64="Auditing of successful/unsuccessful attempts to use open_by_handle_at is enabled on 64bit systems, per V-72129."
    local Failure32="Failed to set auditing of successful/unsuccessful attempts to use open_by_handle_at on 32bit systems, not in compliance with V-72129."
    local Failure64="Failed to set auditing of successful/unsuccessful attempts to use open_by_handle_at on 64bit systems, not in compliance with V-72129."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
    grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
    (uname -p | grep -q 'x86_64' && grep -E -q "$Regex3" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
    (uname -p | grep -q 'x86_64' && grep -E -q "$Regex4" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
    ( (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) && echo "$Success32") || { echo "$Failure32" ; exit 1; }
    echo
    uname -p | grep -q 'x86_64' && ( ( (grep -E -q "$Regex3" /etc/audit/rules.d/audit.rules && grep -E -q "$Regex4" /etc/audit/rules.d/audit.rules) && echo "$Success64") || { echo "$Failure64" ; exit 1; } )
}

#Set audit to audit of successful/unsuccessful attempts to use truncate, V-72131
#function V72131 () {
 #   local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+truncate\s+-F\s+exit=-EPERM\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*(#.*)?$"
 #   local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+truncate\s+-F\s+exit=-EACCES\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*(#.*)?$"
 #   local Regex3="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+truncate\s+-F\s+exit=-EPERM\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*(#.*)?$"
 #   local Regex4="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+truncate\s+-F\s+exit=-EACCES\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*(#.*)?$"
 #   local Success32="Auditing of successful/unsuccessful attempts to use truncate is enabled on 32bit systems, per V-72131."
 #   local Success64="Auditing of successful/unsuccessful attempts to use truncate is enabled on 64bit systems, per V-72131."
 #   local Failure32="Failed to set auditing of successful/unsuccessful attempts to use truncate on 32bit systems, not in compliance with V-72131."
 #   local Failure64="Failed to set auditing of successful/unsuccessful attempts to use truncate on 64bit systems, not in compliance with V-72131."

 #   echo
 #   grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
 #   grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
 #   (uname -p | grep -q 'x86_64' && grep -E -q "$Regex3" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
 #   (uname -p | grep -q 'x86_64' && grep -E -q "$Regex4" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
 #   ( (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) && echo "$Success32") || { echo "$Failure32" ; exit 1; }
 #   echo
 #   uname -p | grep -q 'x86_64' && ( ( (grep -E -q "$Regex3" /etc/audit/rules.d/audit.rules && grep -E -q "$Regex4" /etc/audit/rules.d/audit.rules) && echo "$Success64") || { echo "$Failure64" ; exit 1; } )
#}

#Set audit to audit of successful/unsuccessful attempts to use ftruncate, V-72133
#function V72133 () {
 #   local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+ftruncate\s+-F\s+exit=-EPERM\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*(#.*)?$"
 #   local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+ftruncate\s+-F\s+exit=-EACCES\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*(#.*)?$"
 #   local Regex3="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+ftruncate\s+-F\s+exit=-EPERM\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*(#.*)?$"
 #   local Regex4="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+ftruncate\s+-F\s+exit=-EACCES\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*(#.*)?$"
 #   local Success32="Auditing of successful/unsuccessful attempts to use ftruncate is enabled on 32bit systems, per V-72133."
 #   local Success64="Auditing of successful/unsuccessful attempts to use ftruncate is enabled on 64bit systems, per V-72133."
 #   local Failure32="Failed to set auditing of successful/unsuccessful attempts to use ftruncate on 32bit systems, not in compliance with V-72133."
 #   local Failure64="Failed to set auditing of successful/unsuccessful attempts to use ftruncate on 64bit systems, not in compliance with V-72133."

 #   echo
 #   grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
 #   grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
 #   (uname -p | grep -q 'x86_64' && grep -E -q "$Regex3" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
 #   (uname -p | grep -q 'x86_64' && grep -E -q "$Regex4" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
 #   ( (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) && echo "$Success32") || { echo "$Failure32" ; exit 1; }
 #   echo
 #   uname -p | grep -q 'x86_64' && ( ( (grep -E -q "$Regex3" /etc/audit/rules.d/audit.rules && grep -E -q "$Regex4" /etc/audit/rules.d/audit.rules) && echo "$Success64") || { echo "$Failure64" ; exit 1; } )
#}

#Set audit to audit of successful/unsuccessful attempts to use semanage, V-72135
function V72135 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+path=/usr/sbin/semanage\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+privileged-priv_change\s*(#.*)?$"
    local Success="Auditing of successful/unsuccessful attempts to use semanage is enabled, per V-72135."
    local Failure="Failed to set auditing of successful/unsuccessful attempts to use semanage, not in compliance with V-72135."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F path=/usr/sbin/semanage -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set audit to audit of successful/unsuccessful attempts to use setsebool, V-72137
function V72137 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+path=/usr/sbin/setsebool\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+privileged-priv_change\s*(#.*)?$"
    local Success="Auditing of successful/unsuccessful attempts to use setsebool is enabled, per V-72137."
    local Failure="Failed to set auditing of successful/unsuccessful attempts to use setsebool, not in compliance with V-72137."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F path=/usr/sbin/setsebool -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set audit to audit of successful/unsuccessful attempts to use chcon, V-72139
function V72139 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+path=/usr/bin/chcon\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+privileged-priv_change\s*(#.*)?$"
    local Success="Auditing of successful/unsuccessful attempts to use chcon is enabled, per V-72139."
    local Failure="Failed to set auditing of successful/unsuccessful attempts to use chcon, not in compliance with V-72139."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F path=/usr/bin/chcon -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set audit to audit of successful/unsuccessful attempts to use setfiles, V-72141
function V72141 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+path=/usr/sbin/setfiles\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+privileged-priv_change\s*(#.*)?$"
    local Success="Auditing of successful/unsuccessful attempts to use setfiles is enabled, per V-72141."
    local Failure="Failed to set auditing of successful/unsuccessful attempts to use setfiles, not in compliance with V-72141."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F path=/usr/sbin/setfiles -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set audit to audit when unsuccessful account access events occur, V-72145
function V72145 () {
    local Regex1="^\s*-w\s+/var/run/faillock\s+-p\s+wa\s+-k\s+logins\s*(#.*)?$"
    local Success="Auditing of unsuccessful account access events occur is enabled, per V-72145."
    local Failure="Failed to set auditing of when unsuccessful account access events occur, not in compliance with V-72145."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-w /var/run/faillock -p wa -k logins" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set audit to audit when successful account access events occur, V-72147
#function V72147 () {
 #   local Regex1="^\s*-w\s+/var/log/lastlog\s+-p\s+wa\s+-k\s+logins\s*(#.*)?$"
 #   local Success="Auditing of successful account access events occur is enabled, per V-72147."
 #   local Failure="Failed to set auditing of when successful account access events occur, not in compliance with V-72147."

 #   echo
 #   grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-w /var/log/lastlog -p wa -k logins" >> /etc/audit/rules.d/audit.rules
 #   (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success") || { echo "$Failure" ; exit 1; }
#}

#Set audit to audit of successful/unsuccessful attempts to use passwd, V-72149
function V72149 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+path=/usr/bin/passwd\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+privileged-passwd\s*(#.*)?$"
    local Success="Auditing of successful/unsuccessful attempts to use passwd is enabled, per V-72149."
    local Failure="Failed to set auditing of when successful/unsuccessful attempts to use passwd occur, not in compliance with V-72149."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F path=/usr/bin/passwd -F auid>=1000 -F auid!=4294967295 -k privileged-passwd" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set audit to audit of successful/unsuccessful attempts to use unix_chkpwd, V-72151
function V72151 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+path=/usr/sbin/unix_chkpwd\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+privileged-passwd\s*(#.*)?$"
    local Success="Auditing of successful/unsuccessful attempts to use unix_chkpwd is enabled, per V-72151."
    local Failure="Failed to set auditing of when successful/unsuccessful attempts to use unix_chkpwd occur, not in compliance with V-72151."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F path=/usr/sbin/unix_chkpwd -F auid>=1000 -F auid!=4294967295 -k privileged-passwd" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set audit to audit of successful/unsuccessful attempts to use gpasswd, V-72153
function V72153 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+path=/usr/bin/gpasswd\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+privileged-passwd\s*(#.*)?$"
    local Success="Auditing of successful/unsuccessful attempts to use gpasswd is enabled, per V-72153."
    local Failure="Failed to set auditing of when successful/unsuccessful attempts to use gpasswd occur, not in compliance with V-72153."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F path=/usr/bin/gpasswd -F auid>=1000 -F auid!=4294967295 -k privileged-passwd" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set audit to audit of successful/unsuccessful attempts to use chage, V-72155
function V72155 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+path=/usr/bin/chage\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+privileged-passwd\s*(#.*)?$"
    local Success="Auditing of successful/unsuccessful attempts to use chage is enabled, per V-72155."
    local Failure="Failed to set auditing of when successful/unsuccessful attempts to use chage occur, not in compliance with V-72155."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F path=/usr/bin/chage -F auid>=1000 -F auid!=4294967295 -k privileged-passwd" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set audit to audit of successful/unsuccessful attempts to use userhelper, V-72157
function V72157 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+path=/usr/sbin/userhelper\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+privileged-passwd\s*(#.*)?$"
    local Success="Auditing of successful/unsuccessful attempts to use userhelper, per V-72157."
    local Failure="Failed to set auditing of when successful/unsuccessful attempts to use userhelper occur, not in compliance with V-72157."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F path=/usr/sbin/userhelper -F auid>=1000 -F auid!=4294967295 -k privileged-passwd" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set audit to audit of successful/unsuccessful attempts to use su, V-72159
function V72159 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+path=/usr/bin/su\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+privileged-passwd\s*(#.*)?$"
    local Success="Auditing of successful/unsuccessful attempts to use su, per V-72159."
    local Failure="Failed to set auditing of when successful/unsuccessful attempts to use su occur, not in compliance with V-72159."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F path=/usr/bin/su -F auid>=1000 -F auid!=4294967295 -k privileged-passwd" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set audit to audit of successful/unsuccessful attempts to use sudo, V-72161
function V72161 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+path=/usr/bin/sudo\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+privileged-passwd\s*(#.*)?$"
    local Success="Auditing of successful/unsuccessful attempts to use sudo, per V-72161."
    local Failure="Failed to set auditing of when successful/unsuccessful attempts to use sudo occur, not in compliance with V-72161."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F path=/usr/bin/sudo -F auid>=1000 -F auid!=4294967295 -k privileged-passwd" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set audit to audit of successful/unsuccessful access attempts to /etc/sudoers and /etc/sudoers.d, V-72163
function V72163 () {
    local Regex1="^\s*-w\s+/etc/sudoers\s+-p\s+wa\s+-k\s+privileged-actions\s*(#.*)?$"
    local Regex2="^\s*-w\s+/etc/sudoers.d/\s+-p\s+wa\s+-k\s+privileged-actions\s*(#.*)?$"
    local Success="Auditing of the successful/unsuccessful access attempts to /etc/sudoers and /etc/sudoers.d, per V-72163."
    local Failure="Failed to set the auditing of successful/unsuccessful attempts to access /etc/sudoers and /etc/sudoers.d, not in compliance with V-72163."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-w /etc/sudoers -p wa -k privileged-actions" >> /etc/audit/rules.d/audit.rules
    grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules || echo "-w /etc/sudoers.d/ -p wa -k privileged-actions" >> /etc/audit/rules.d/audit.rules
    ( (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set audit to audit of successful/unsuccessful attempts to use newgrp, V-72165
function V72165 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+path=/usr/bin/newgrp\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+privileged-priv_change\s*(#.*)?$"
    local Success="Auditing of successful/unsuccessful attempts to use newgrp, per V-72165."
    local Failure="Failed to set auditing of when successful/unsuccessful attempts to use newgrp occur, not in compliance with V-72165."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F path=/usr/bin/newgrp -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set audit to audit of successful/unsuccessful attempts to use chsh, V-72167
function V72167 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+path=/usr/bin/chsh\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+privileged-priv_change\s*(#.*)?$"
    local Success="Auditing of successful/unsuccessful attempts to use chsh, per V-72167."
    local Failure="Failed to set auditing of when successful/unsuccessful attempts to use chsh occur, not in compliance with V-72167."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F path=/usr/bin/chsh -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set audit to audit of successful/unsuccessful attempts to use mount, V-72171
function V72171 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+mount\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+privileged-mount\s*(#.*)?$"
    local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+mount\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+privileged-mount\s*(#.*)?$"
    local Regex3="^\s*-a\s+always,exit\s+-F\s+path=/usr/bin/mount\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+privileged-mount\s*(#.*)?$"
    local Success32="Auditing of the successful/unsuccessful access attempts to use mount on 32bit systems, per V-72171."
    local Success64="Auditing of the successful/unsuccessful access attempts to use mount on 64bit systems, per V-72171."
    local Failure32="Failed to set the auditing of successful/unsuccessful attempts to use mount on 32bit systems, not in compliance with V-72171."
    local Failure64="Failed to set the auditing of successful/unsuccessful attempts to use mount on 64bit systems, not in compliance with V-72171."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k privileged-mount" >> /etc/audit/rules.d/audit.rules
    (uname -p | grep -q 'x86_64' && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k privileged-mount" >> /etc/audit/rules.d/audit.rules
    grep -E -q "$Regex3" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F path=/usr/bin/mount -F auid>=1000 -F auid!=4294967295 -k privileged-mount" >> /etc/audit/rules.d/audit.rules
    ( (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && grep -E -q "$Regex3" /etc/audit/rules.d/audit.rules) && echo "$Success32") || { echo "$Failure32" ; exit 1; }
    echo
    uname -p | grep -q 'x86_64' && ( (grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules && echo "$Success64") || { echo "$Failure64" ; exit 1; } )
}

#Set audit to audit of successful/unsuccessful attempts to use umount, V-72173
function V72173 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+path=/usr/bin/umount\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+privileged-mount\s*(#.*)?$"
    local Success="Auditing of successful/unsuccessful attempts to use umount, per V-72173."
    local Failure="Failed to set auditing of when successful/unsuccessful attempts to use umount occur, not in compliance with V-72173."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F path=/usr/bin/umount -F auid>=1000 -F auid!=4294967295 -k privileged-mount" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set audit to audit of successful/unsuccessful attempts to use postdrop, V-72175
function V72175 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+path=/usr/sbin/postdrop\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+privileged-postfix\s*(#.*)?$"
    local Success="Auditing of successful/unsuccessful attempts to use postdrop, per V-72175."
    local Failure="Failed to set auditing of when successful/unsuccessful attempts to use postdrop occur, not in compliance with V-72175."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F path=/usr/sbin/postdrop -F auid>=1000 -F auid!=4294967295 -k privileged-postfix" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set audit to audit of successful/unsuccessful attempts to use postqueue, V-72177
function V72177 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+path=/usr/sbin/postqueue\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+privileged-postfix\s*(#.*)?$"
    local Success="Auditing of successful/unsuccessful attempts to use postqueue, per V-72177."
    local Failure="Failed to set auditing of when successful/unsuccessful attempts to use postqueue occur, not in compliance with V-72177."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F path=/usr/sbin/postqueue -F auid>=1000 -F auid!=4294967295 -k privileged-postfix" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set audit to audit of successful/unsuccessful attempts to use ssh-keysign, V-72179
#function V72179 () {
#    local Regex1="^\s*-a\s+always,exit\s+-F\s+path=/usr/libexec/openssh/ssh-keysign\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+privileged-ssh\s*(#.*)?$"
#    local Success="Auditing of successful/unsuccessful attempts to use ssh-keysign, per V-72179."
#    local Failure="Failed to set auditing of when successful/unsuccessful attempts to use ssh-keysign occur, not in compliance with V-72179."

#    echo
#    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F path=/usr/libexec/openssh/ssh-keysign -F auid>=1000 -F auid!=4294967295 -k privileged-ssh" >> /etc/audit/rules.d/audit.rules
#    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success") || { echo "$Failure" ; exit 1; }
#}

#Set audit to audit of successful/unsuccessful attempts to use crontab, V-72183
function V72183 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+path=/usr/bin/crontab\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+privileged-cron\s*(#.*)?$"
    local Success="Auditing of successful/unsuccessful attempts to use crontab, per V-72183."
    local Failure="Failed to set auditing of when successful/unsuccessful attempts to use crontab occur, not in compliance with V-72183."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F path=/usr/bin/crontab -F auid>=1000 -F auid!=4294967295 -k privileged-cron" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set audit to audit of successful/unsuccessful attempts to use pam_timestamp_check, V-72185
function V72185 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+path=/usr/sbin/pam_timestamp_check\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+privileged-pam\s*(#.*)?$"
    local Success="Auditing of successful/unsuccessful attempts to use pam_timestamp_check, per V-72185."
    local Failure="Failed to set auditing of when successful/unsuccessful attempts to use pam_timestamp_check occur, not in compliance with V-72185."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F path=/usr/sbin/pam_timestamp_check -F auid>=1000 -F auid!=4294967295 -k privileged-pam" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set audit to audit of successful/unsuccessful attempts to use init_module, V-72187
function V72187 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+init_module\s+-k\s+module-change\s*(#.*)?$"
    local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+init_module\s+-k\s+module-change\s*(#.*)?$"
    local Regex3="^\s*-a\s+always,exit\s+-F\s+path=/usr/bin/mount\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+privileged-mount\s*(#.*)?$"
    local Success32="Auditing of the successful/unsuccessful access attempts to use init_module on 32bit systems, per V-72187."
    local Success64="Auditing of the successful/unsuccessful access attempts to use init_module on 64bit systems, per V-72187."
    local Failure32="Failed to set the auditing of successful/unsuccessful attempts to use init_module on 32bit systems, not in compliance with V-72187."
    local Failure64="Failed to set the auditing of successful/unsuccessful attempts to use init_module on 64bit systems, not in compliance with V-72187."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S init_module -k module-change" >> /etc/audit/rules.d/audit.rules
    (uname -p | grep -q 'x86_64' && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S init_module -k module-change" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success32") || { echo "$Failure32" ; exit 1; }
    echo
    uname -p | grep -q 'x86_64' && ( (grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules && echo "$Success64") || { echo "$Failure64" ; exit 1; } )
}

#Set audit to audit of successful/unsuccessful attempts to use delete_module, V-72189
function V72189 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+delete_module\s+-k\s+module-change\s*(#.*)?$"
    local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+delete_module\s+-k\s+module-change\s*(#.*)?$"
    local Success32="Auditing of the successful/unsuccessful access attempts to use delete_module on 32bit systems, per V-72189."
    local Success64="Auditing of the successful/unsuccessful access attempts to use delete_module on 64bit systems, per V-72189."
    local Failure32="Failed to set the auditing of successful/unsuccessful attempts to use delete_module on 32bit systems, not in compliance V-72189."
    local Failure64="Failed to set the auditing of successful/unsuccessful attempts to use delete_module on 64bit systems, not in compliance V-72189."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S delete_module -k module-change" >> /etc/audit/rules.d/audit.rules
    (uname -p | grep -q 'x86_64' && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S delete_module -k module-change" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success32") || { echo "$Failure32" ; exit 1; }
    echo
    uname -p | grep -q 'x86_64' && ( (grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules && echo "$Success64") || { echo "$Failure64" ; exit 1; } )
}

#Set audit to audit of successful/unsuccessful attempts to use kmod, V-72191
function V72191 () {
    local Regex1="^\s*-w\s+/usr/bin/kmod\s+-p\s+x\s+-F\s+auid!=4294967295\s+-k\s+module-change\s*(#.*)?$"
    local Success="Auditing of successful/unsuccessful attempts to use kmod, per V-72191."
    local Failure="Failed to set auditing of when successful/unsuccessful attempts to use kmod occur , not in compliance V-72191."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-w /usr/bin/kmod -p x -F auid!=4294967295 -k module-change" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set audit to audit all account creations, modifications, disabling, and termination events that affect "/etc/passwd", V-72197
#function V72197 () {
#    local Regex1="^\s*-w\s+/etc/passwd\s+-p\s+wa\s+-k\s+identity\s*(#.*)?$"
#    local Success="Auditing of all account creations, modifications, disabling, and termination events that affect '/etc/passwd', per V-72197."
#    local Failure="Failed to set auditing of all account creations, modifications, disabling, and termination events that affect '/etc/passwd', not in compliance V-72197."

#    echo
#    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-w /etc/passwd -p wa -k identity" >> /etc/audit/rules.d/audit.rules
#    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success") || { echo "$Failure" ; exit 1; }
#}

#Set audit to audit of successful/unsuccessful attempts to use rename, V-72199
function V72199 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+rename\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+delete\s*(#.*)?$"
    local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+rename\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+delete\s*(#.*)?$"
    local Success32="Auditing of the successful/unsuccessful access attempts to use rename on 32bit systems, per V-72199."
    local Success64="Auditing of the successful/unsuccessful access attempts to use rename on 64bit systems, per V-72199."
    local Failure32="Failed to set the auditing of successful/unsuccessful attempts to use rename on 32bit systems, not in compliance V-72199."
    local Failure64="Failed to set the auditing of successful/unsuccessful attempts to use rename on 64bit systems, not in compliance V-72199."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S rename -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/audit.rules
    (uname -p | grep -q 'x86_64' && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S rename -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success32") || { echo "$Failure32" ; exit 1; }
    echo
    uname -p | grep -q 'x86_64' && ( (grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules && echo "$Success64") || { echo "$Failure64" ; exit 1; } )
}

#Set audit to audit of successful/unsuccessful attempts to use renameat, V-72201
function V72201 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+renameat\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+delete\s*(#.*)?$"
    local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+renameat\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+delete\s*(#.*)?$"
    local Success32="Auditing of the successful/unsuccessful access attempts to use renameat on 32bit systems, per V-72201."
    local Success64="Auditing of the successful/unsuccessful access attempts to use renameat on 64bit systems, per V-72201."
    local Failure32="Failed to set the auditing of successful/unsuccessful attempts to use renameat on 32bit systems, not in compliance V-72201."
    local Failure64="Failed to set the auditing of successful/unsuccessful attempts to use renameat on 32bit systems, not in compliance V-72201."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/audit.rules
    (uname -p | grep -q 'x86_64' && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success32") || { echo "$Failure32" ; exit 1; }
    echo
    uname -p | grep -q 'x86_64' && ( (grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules && echo "$Success64") || { echo "$Failure64" ; exit 1; } )
}

#Set audit to audit of successful/unsuccessful attempts to use rmdir, V-72203
function V72203 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+rmdir\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+delete\s*(#.*)?$"
    local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+rmdir\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+delete\s*(#.*)?$"
    local Success32="Auditing of the successful/unsuccessful access attempts to use rmdir on 32bit systems, per V-72203."
    local Success64="Auditing of the successful/unsuccessful access attempts to use rmdir on 64bit systems, per V-72203."
    local Failure32="Failed to set the auditing of successful/unsuccessful attempts to use rmdir on 32bit systems, not in compliance V-72203."
    local Failure64="Failed to set the auditing of successful/unsuccessful attempts to use rmdir on 64bit systems, not in compliance V-72203."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S rmdir -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/audit.rules
    (uname -p | grep -q 'x86_64' && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S rmdir -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success32") || { echo "$Failure32" ; exit 1; }
    echo
    uname -p | grep -q 'x86_64' && ( (grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules && echo "$Success64") || { echo "$Failure64" ; exit 1; } )
}

#Set audit to audit of successful/unsuccessful attempts to use unlink, V-72205
function V72205 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+unlink\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+delete\s*(#.*)?$"
    local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+unlink\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+delete\s*(#.*)?$"
    local Success32="Auditing of the successful/unsuccessful access attempts to use unlink on 32bit systems, per V-72205."
    local Success64="Auditing of the successful/unsuccessful access attempts to use unlink on 64bit systems, per V-72205."
    local Failure32="Failed to set the auditing of successful/unsuccessful attempts to use unlink on 32bit systems, not in compliance V-72205."
    local Failure64="Failed to set the auditing of successful/unsuccessful attempts to use unlink on 64bit systems, not in compliance V-72205."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S unlink -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/audit.rules
    (uname -p | grep -q 'x86_64' && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S unlink -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success32") || { echo "$Failure32" ; exit 1; }
    echo
    uname -p | grep -q 'x86_64' && ( (grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules && echo "$Success64") || { echo "$Failure64" ; exit 1; } )
}

#Set audit to audit of successful/unsuccessful attempts to use unlinkat, V-72207
function V72207 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+unlinkat\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+delete\s*(#.*)?$"
    local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+unlinkat\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+delete\s*(#.*)?$"
    local Success32="Auditing of the successful/unsuccessful access attempts to use unlink on 32bit systems, per V-72207."
    local Success64="Auditing of the successful/unsuccessful access attempts to use unlink on 64bit systems, per V-72207."
    local Failure32="Failed to set the auditing of successful/unsuccessful attempts to use unlink on 32bit systems, not in compliance V-72207."
    local Failure64="Failed to set the auditing of successful/unsuccessful attempts to use unlink on 64bit systems, not in compliance V-72207."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S unlinkat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/audit.rules
    (uname -p | grep -q 'x86_64' && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S unlinkat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success32") || { echo "$Failure32" ; exit 1; }
    echo
    uname -p | grep -q 'x86_64' && ( (grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules && echo "$Success64") || { echo "$Failure64" ; exit 1; } )
}

#Set timeout to 600sec, V-72223
function V72223 () {
    local Success="Set terminal timeout period to 600secs, per V-72223."
    local Failure="Failed to set terminal timeout period to 600secs, not in compliance V-72223."

    echo
    if [ -f "/etc/profile.d/tmout.sh" ]
    then
        grep -E -q "^\s*TMOUT=600\s*(#.*)?$" /etc/profile.d/tmout.sh || echo "TMOUT=600" >> /etc/profile.d/tmout.sh
        grep -E -q "^\s*readonly\s*TMOUT\s*(#.*)?$" /etc/profile.d/tmout.sh || echo "readonly TMOUT" >> /etc/profile.d/tmout.sh
        grep -E -q "^\s*export\s*TMOUT\s*(#.*)?$" /etc/profile.d/tmout.sh || echo "export TMOUT" >> /etc/profile.d/tmout.sh
    else
        echo -e "#!/bin/bash\n\nTMOUT=600\nreadonly TMOUT\nexport TMOUT" >> /etc/profile.d/tmout.sh
    fi
    ( (grep -E -q "^\s*TMOUT=600?\s*$" /etc/profile.d/tmout.sh && grep -E -q "^\s*readonly\s*TMOUT?\s*$" /etc/profile.d/tmout.sh && grep -E -q "^\s*export\s*TMOUT\s*$" /etc/profile.d/tmout.sh) && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set timeout period, V-72237
#function V72237 () {
#    local Regex1="^(\s*)#ClientAliveInterval\s+\S+(\s*#.*)?\s*$"
#    local Regex2="s/^(\s*)#ClientAliveInterval\s+\S+(\s*#.*)?\s*$/\ClientAliveInterval 600\2/"
#    local Regex3="^(\s*)ClientAliveInterval\s+\S+(\s*#.*)?\s*$"
#    local Regex4="s/^(\s*)ClientAliveInterval\s+\S+(\s*#.*)?\s*$/\ClientAliveInterval 600\2/"
#    local Regex5="^(\s*)ClientAliveInterval\s*600?\s*$"
#    local Success="Set SSH user timeout period to 600secs, per V-72237."
#    local Failure="Failed to set SSH user timeout period to 600secs, not in compliance V-72237."

#    echo
#    ( (grep -E -q "$Regex1" /etc/ssh/sshd_config && sed -ri "$Regex2" /etc/ssh/sshd_config) || (grep -E -q "$Regex3" /etc/ssh/sshd_config && sed -ri "$Regex4" /etc/ssh/sshd_config) ) || echo "ClientAliveInterval 600" >> /etc/ssh/sshd_config
#    (grep -E -q "$Regex5" /etc/ssh/sshd_config && echo "$Success") || { echo "$Failure" ; exit 1; }
#}

#Set terminate user session after timeout, V-72241
#function V72241 () {
 #   local Regex1="^(\s*)#ClientAliveCountMax\s+\S+(\s*#.*)?\s*$"
 #   local Regex2="s/^(\s*)#ClientAliveCountMax\s+\S+(\s*#.*)?\s*$/\ClientAliveCountMax 0\2/"
 #   local Regex3="s/^(\s*)ClientAliveCountMax\s+\S+(\s*#.*)?\s*$/\ClientAliveCountMax 0\2/"
 #   local Regex4="^(\s*)ClientAliveCountMax\s*0?\s*$"
 #   local Success="Set SSH user sesstions to terminate after session timeout, per V-72241."
 #   local Failure="Failed to set SSH user sesstions to terminate after session timeout, not in compliance V-72241."

 #   echo
 #   ( (grep -E -q "$Regex1" /etc/ssh/sshd_config && sed -ri "$Regex2" /etc/ssh/sshd_config) || (grep -E -q "$Regex1" /etc/ssh/sshd_config && sed -ri "$Regex3" /etc/ssh/sshd_config) ) || echo "ClientAliveCountMax 0" >> /etc/ssh/sshd_config
 #   (grep -E -q "$Regex4" /etc/ssh/sshd_config && echo "$Success") || { echo "$Failure" ; exit 1; }
#}

#Set to not allow authentication using known host, V-72243
function V72243 () {
    local Regex1="^(\s*)#IgnoreRhosts\s+\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)#IgnoreRhosts\s+\S+(\s*#.*)?\s*$/\IgnoreRhosts yes\2/"
    local Regex3="^(\s*)IgnoreRhosts\s+\S+(\s*#.*)?\s*$"
    local Regex4="s/^(\s*)IgnoreRhosts\s+\S+(\s*#.*)?\s*$/\IgnoreRhosts yes\2/"
    local Regex5="^(\s*)IgnoreRhosts\s*yes?\s*$"
    local Success="Set SSH to not allow rhosts authentication, per V-72243."
    local Failure="Failed to set SSH to not allow rhosts authentication, not in compliance V-72243."

    echo
    ( (grep -E -q "$Regex1" /etc/ssh/sshd_config && sed -ri "$Regex2" /etc/ssh/sshd_config) || (grep -E -q "$Regex3" /etc/ssh/sshd_config && sed -ri "$Regex4" /etc/ssh/sshd_config) ) || echo "IgnoreRhosts yes" >> /etc/ssh/sshd_config
    (grep -E -q "$Regex5" /etc/ssh/sshd_config && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set to provide feedback on last account access, V-72245
function V72245 () {
    local Regex1="^(\s*)#PrintLastLog\s+\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)#PrintLastLog\s+\S+(\s*#.*)?\s*$/\PrintLastLog yes\2/"
    local Regex3="^(\s*)PrintLastLog\s+\S+(\s*#.*)?\s*$"
    local Regex4="s/^(\s*)PrintLastLog\s+\S+(\s*#.*)?\s*$/\PrintLastLog yes\2/"
    local Regex5="^(\s*)PrintLastLog\s*yes?\s*$"
    local Success="Set SSH to inform users of when the last time their account connected, per V-72245."
    local Failure="Failed to set SSH to inform users of when the last time their account connected, not in compliance V-72245."

    echo
    ( (grep -E -q "$Regex1" /etc/ssh/sshd_config && sed -ri "$Regex2" /etc/ssh/sshd_config) || (grep -E -q "$Regex3" /etc/ssh/sshd_config && sed -ri "$Regex4" /etc/ssh/sshd_config) ) || echo "PrintLastLog yes" >> /etc/ssh/sshd_config
    (grep -E -q "$Regex5" /etc/ssh/sshd_config && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set SSH to prevent root logon, V-72247
#function V72247 () {
#    local Regex1="^(\s*)#PermitRootLogin\s+\S+(\s*#.*)?\s*$"
#    local Regex2="s/^(\s*)#PermitRootLogin\s+\S+(\s*#.*)?\s*$/\PermitRootLogin no\2/"
#    local Regex3="^(\s*)PermitRootLogin\s+\S+(\s*#.*)?\s*$"
#    local Regex4="s/^(\s*)PermitRootLogin\s+\S+(\s*#.*)?\s*$/\PermitRootLogin no\2/"
#    local Regex5="^(\s*)PermitRootLogin\s*no?\s*$"
#    local Success="Set SSH to not allow connections from root, per V-72247."
#    local Failure="Failed to set SSH to not allow connections from root, not in compliance V-72247."

#    echo
#    ( (grep -E -q "$Regex1" /etc/ssh/sshd_config && sed -ri "$Regex2" /etc/ssh/sshd_config) || (grep -E -q "$Regex3" /etc/ssh/sshd_config && sed -ri "$Regex4" /etc/ssh/sshd_config) ) || echo "PermitRootLogin no" >> /etc/ssh/sshd_config
#    (grep -E -q "$Regex5" /etc/ssh/sshd_config && echo "$Success") || { echo "$Failure" ; exit 1; }
#}

#Set to not allow authentication using known host, V-72249
function V72249 {
    local Regex1="^(\s*)#IgnoreUserKnownHosts\s+\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)#IgnoreUserKnownHosts\s+\S+(\s*#.*)?\s*$/\IgnoreUserKnownHosts yes\2/"
    local Regex3="^(\s*)IgnoreUserKnownHosts\s+\S+(\s*#.*)?\s*$"
    local Regex4="s/^(\s*)IgnoreUserKnownHosts\s+\S+(\s*#.*)?\s*$/\IgnoreUserKnownHosts yes\2/"
    local Regex5="^(\s*)IgnoreUserKnownHosts\s*yes?\s*$"
    local Success="Set SSH to not allow authentication using known host authentication, per V-72249."
    local Failure="Failed to set SSH to not allow authentication using known host authentication, not in compliance V-72249."

    echo
    ( (grep -E -q "$Regex1" /etc/ssh/sshd_config && sed -ri "$Regex2" /etc/ssh/sshd_config) || (grep -E -q "$Regex3" /etc/ssh/sshd_config && sed -ri "$Regex4" /etc/ssh/sshd_config) ) || echo "IgnoreUserKnownHosts yes" >> /etc/ssh/sshd_config
    (grep -E -q "$Regex5" /etc/ssh/sshd_config && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Do not permit GSSAPI auth, V-72259
function V72259 () {
    local Regex1="^(\s*)GSSAPIAuthentication\s+\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)GSSAPIAuthentication\s+\S+(\s*#.*)?\s*$/\GSSAPIAuthentication no\2/"
    local Regex3="^(\s*)GSSAPIAuthentication\s*no?\s*$"
    local Success="Set SSH to not allow authentication using GSSAPI authentication, per V-72259."
    local Failure="Failed to set SSH to not allow authentication using GSSAPI authentication, not in compliance V-72259."

    echo
    (grep -E -q "$Regex1" /etc/ssh/sshd_config && sed -ri "$Regex2" /etc/ssh/sshd_config) || echo "GSSAPIAuthentication no" >> /etc/ssh/sshd_config
    (grep -E -q "$Regex3" /etc/ssh/sshd_config && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Disable Kerberos over SSH, V-72261
#function V72261 () {
#    local Regex1="^(\s*)#KerberosAuthentication\s+\S+(\s*#.*)?\s*$"
#    local Regex2="s/^(\s*)#KerberosAuthentication\s+\S+(\s*#.*)?\s*$/\KerberosAuthentication no\2/"
#    local Regex3="^(\s*)KerberosAuthentication\s+\S+(\s*#.*)?\s*$"
#    local Regex4="s/^(\s*)KerberosAuthentication\s+\S+(\s*#.*)?\s*$/\KerberosAuthentication no\2/"
#    local Regex5="^(\s*)KerberosAuthentication\s*no?\s*$"
#    local Success="Set SSH to not allow authentication using KerberosAuthentication authentication, per V-72261."
#    local Failure="Failed to set SSH to not allow authentication using KerberosAuthentication authentication, not in compliance V-72261."

#    echo
#   ( (grep -E -q "$Regex1" /etc/ssh/sshd_config && sed -ri "$Regex2" /etc/ssh/sshd_config) || (grep -E -q "$Regex3" /etc/ssh/sshd_config && sed -ri "$Regex4" /etc/ssh/sshd_config) ) || echo "KerberosAuthentication no" >> /etc/ssh/sshd_config
#   (grep -E -q "$Regex5" /etc/ssh/sshd_config && echo "$Success") || { echo "$Failure" ; exit 1; }
#}

#Set SSH to perform strict mode checking of home dir configuraiton files, V-72263
function V72263 () {
    local Regex1="^(\s*)#StrictModes\s+\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)#StrictModes\s+\S+(\s*#.*)?\s*$/\StrictModes yes\2/"
    local Regex3="^(\s*)StrictModes\s+\S+(\s*#.*)?\s*$"
    local Regex4="s/^(\s*)StrictModes\s+\S+(\s*#.*)?\s*$/\StrictModes yes\2/"
    local Regex5="^(\s*)StrictModes\s*yes?\s*$"
    local Success="Set SSH to perform strict mode checking of the home directory configuration files, per V-72263."
    local Failure="Failed to set SSH to perform strict mode checking of the home directory configuration files, not in compliance V-72263."

    echo
    ( (grep -E -q "$Regex1" /etc/ssh/sshd_config && sed -ri "$Regex2" /etc/ssh/sshd_config) || (grep -E -q "$Regex3" /etc/ssh/sshd_config && sed -ri "$Regex4" /etc/ssh/sshd_config) ) || echo "StrictModes yes" >> /etc/ssh/sshd_config
    (grep -E -q "$Regex5" /etc/ssh/sshd_config && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set SSH to perform privilege separation, V-72267
function V72267 () {
    local Regex1="^(\s*)#Compression\s+\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)#Compression\s+\S+(\s*#.*)?\s*$/\Compression delayed\2/"
    local Regex3="^(\s*)Compression\s+\S+(\s*#.*)?\s*$"
    local Regex4="s/^(\s*)Compression\s+\S+(\s*#.*)?\s*$/\Compression delayed\2/"
    local Regex5="^(\s*)Compression\s*delayed?\s*$"
    local Success="Set SSH to only allow compression after successful authentication, per V-72267."
    local Failure="Failed to set SSH to only allow compression after successful authentication, not in compliance V-72267."

    echo
    ( (grep -E -q "$Regex1" /etc/ssh/sshd_config && sed -ri "$Regex2" /etc/ssh/sshd_config) || (grep -E -q "$Regex3" /etc/ssh/sshd_config && sed -ri "$Regex4" /etc/ssh/sshd_config) ) || echo "Compression delayed" >> /etc/ssh/sshd_config
    (grep -E -q "$Regex5" /etc/ssh/sshd_config && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set OS to not accept IPv4 source-routed packets, V-72283
#function V72283 () {
#    local Regex1="^(\s*)#net.ipv4.conf.all.accept_source_route\s+\S+(\s*#.*)?\s*$"
#    local Regex2="s/^(\s*)#net.ipv4.conf.all.accept_source_route\s+\S+(\s*#.*)?\s*$/\net.ipv4.conf.all.accept_source_route = 0\2/"
#    local Regex3="^(\s*)net.ipv4.conf.all.accept_source_route\s+\S+(\s*#.*)?\s*$"
#    local Regex4="s/^(\s*)net.ipv4.conf.all.accept_source_route\s+\S+(\s*#.*)?\s*$/\net.ipv4.conf.all.accept_source_route = 0\2/"
#    local Regex5="^(\s*)net.ipv4.conf.all.accept_source_route\s*=\s*0?\s*$"
#    local Success="Set system to not accept IPv4 source-routed packets, per V-72283."
#    local Failure="Failed to set system to not accept IPv4 source-routed packets, not in compliance V-72283."

#    echo
#    ( (grep -E -q "$Regex1" /etc/sysctl.conf && sed -ri "$Regex2" /etc/sysctl.conf) || (grep -E -q "$Regex3" /etc/sysctl.conf && sed -ri "$Regex4" /etc/sysctl.conf) ) || echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
#    (grep -E -q "$Regex5" /etc/sysctl.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
#}

#Set OS to not accept IPv4 source-routed packets by default, V-72285
#function V72285 () {
#    local Regex1="^(\s*)#net.ipv4.conf.default.accept_source_route\s+\S+(\s*#.*)?\s*$"
#    local Regex2="s/^(\s*)#net.ipv4.conf.default.accept_source_route\s+\S+(\s*#.*)?\s*$/\net.ipv4.conf.default.accept_source_route = 0\2/"
#    local Regex3="^(\s*)net.ipv4.conf.default.accept_source_route\s+\S+(\s*#.*)?\s*$"
#    local Regex4="s/^(\s*)net.ipv4.conf.default.accept_source_route\s+\S+(\s*#.*)?\s*$/\net.ipv4.conf.default.accept_source_route = 0\2/"
#    local Regex5="^(\s*)net.ipv4.conf.default.accept_source_route\s*=\s*0?\s*$"
#    local Success="Set system to not accept IPv4 source-routed packets by default, per V-72285."
#    local Failure="Failed to set system to not accept IPv4 source-routed packets by default, not in compliance V-72285."

#    echo
#    ( (grep -E -q "$Regex1" /etc/sysctl.conf && sed -ri "$Regex2" /etc/sysctl.conf) || (grep -E -q "$Regex3" /etc/sysctl.conf && sed -ri "$Regex4" /etc/sysctl.conf) ) || echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
#    (grep -E -q "$Regex5" /etc/sysctl.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
#}

#Set OS to not respond to ICMP, V-72287
#function V72287 () {
 #   local Regex1="^(\s*)#net.ipv4.icmp_echo_ignore_broadcasts\s+\S+(\s*#.*)?\s*$"
 #   local Regex2="s/^(\s*)#net.ipv4.icmp_echo_ignore_broadcasts\s+\S+(\s*#.*)?\s*$/\net.ipv4.icmp_echo_ignore_broadcasts = 1\2/"
 #   local Regex3="^(\s*)net.ipv4.icmp_echo_ignore_broadcasts\s+\S+(\s*#.*)?\s*$"
 #   local Regex4="s/^(\s*)net.ipv4.icmp_echo_ignore_broadcasts\s+\S+(\s*#.*)?\s*$/\net.ipv4.icmp_echo_ignore_broadcasts = 1\2/"
 #   local Regex5="^(\s*)net.ipv4.icmp_echo_ignore_broadcasts\s*=\s*1?\s*$"
 #   local Success="Set system to not respond to ICMP on IPv4, per V-72287."
 #   local Failure="Failed to set system to not respond to ICMP on IPv4, not in compliance V-72287."

  #  echo
  #  ( (grep -E -q "$Regex1" /etc/sysctl.conf && sed -ri "$Regex2" /etc/sysctl.conf) || (grep -E -q "$Regex3" /etc/sysctl.conf && sed -ri "$Regex4" /etc/sysctl.conf) ) || echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
  #  (grep -E -q "$Regex5" /etc/sysctl.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
#}

#Set OS to not accept ICMP redirects, V-72289
#function V72289 () {
  #  local Regex1="^(\s*)#net.ipv4.conf.default.accept_redirects\s+\S+(\s*#.*)?\s*$"
  #  local Regex2="s/^(\s*)#net.ipv4.conf.default.accept_redirects\s+\S+(\s*#.*)?\s*$/\net.ipv4.conf.default.accept_redirects = 0\2/"
  #  local Regex3="^(\s*)net.ipv4.conf.default.accept_redirects\s+\S+(\s*#.*)?\s*$"
  #  local Regex4="s/^(\s*)net.ipv4.conf.default.accept_redirects\s+\S+(\s*#.*)?\s*$/\net.ipv4.conf.default.accept_redirects = 0\2/"
  #  local Regex5="^(\s*)net.ipv4.conf.default.accept_redirects\s*=\s*0?\s*$"
  #  local Success="Set system to not accept ICMP redirects on IPv4, per V-72289."
  #  local Failure="Failed to set system to not accept ICMP redirects on IPv4, not in compliance V-72289."

   # echo
   # ( (grep -E -q "$Regex1" /etc/sysctl.conf && sed -ri "$Regex2" /etc/sysctl.conf) || (grep -E -q "$Regex3" /etc/sysctl.conf && sed -ri "$Regex4" /etc/sysctl.conf) ) || echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
   # (grep -E -q "$Regex5" /etc/sysctl.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
#}

#Set OS to not allow interfaces to perform ICMP redirects, V-72291
#function V72291 () {
 #   local Regex1="^(\s*)#net.ipv4.conf.default.send_redirects\s+\S+(\s*#.*)?\s*$"
 #   local Regex2="s/^(\s*)#net.ipv4.conf.default.send_redirects\s+\S+(\s*#.*)?\s*$/\net.ipv4.conf.default.send_redirects = 0\2/"
 #   local Regex3="^(\s*)net.ipv4.conf.default.send_redirects\s+\S+(\s*#.*)?\s*$"
 #   local Regex4="s/^(\s*)net.ipv4.conf.default.send_redirects\s+\S+(\s*#.*)?\s*$/\net.ipv4.conf.default.send_redirects = 0\2/"
 #   local Regex5="^(\s*)net.ipv4.conf.default.send_redirects\s*=\s*0?\s*$"
 #   local Success="Set system to not peform ICMP redirects on IPv4 by default, per V-72291."
 #   local Failure="Failed to set system to not peform ICMP redirects on IPv4 by default, not in compliance V-72291."

 #   echo
 #   ( (grep -E -q "$Regex1" /etc/sysctl.conf && sed -ri "$Regex2" /etc/sysctl.conf) || (grep -E -q "$Regex3" /etc/sysctl.conf && sed -ri "$Regex4" /etc/sysctl.conf) ) || echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf
 #   (grep -E -q "$Regex5" /etc/sysctl.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
#}

#Set OS to not allow sending ICMP redirects, V-72293
#function V72293 () {
#    local Regex1="^(\s*)#net.ipv4.conf.all.send_redirects\s+\S+(\s*#.*)?\s*$"
#    local Regex2="s/^(\s*)#net.ipv4.conf.all.send_redirects\s+\S+(\s*#.*)?\s*$/\net.ipv4.conf.all.send_redirects = 0\2/"
#    local Regex3="^(\s*)net.ipv4.conf.all.send_redirects\s+\S+(\s*#.*)?\s*$"
#    local Regex4="s/^(\s*)net.ipv4.conf.all.send_redirects\s+\S+(\s*#.*)?\s*$/\net.ipv4.conf.all.send_redirects = 0\2/"
#    local Regex5="^(\s*)net.ipv4.conf.all.send_redirects\s*=\s*0?\s*$"
#    local Success="Set system to not send ICMP redirects on IPv4, per V-72293."
#    local Failure="Failed to set system to not send ICMP redirects on IPv4, not in compliance V-72293."

#    echo
#    ( (grep -E -q "$Regex1" /etc/sysctl.conf && sed -ri "$Regex2" /etc/sysctl.conf) || (grep -E -q "$Regex3" /etc/sysctl.conf && sed -ri "$Regex4" /etc/sysctl.conf) ) || echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
#    (grep -E -q "$Regex5" /etc/sysctl.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
#}

#Prevent unrestricted mail relaying, V-72297
#function V72297 () {
#    local Regex1="^(\s*)smtpd_client_restrictions\s*=\s*permit_mynetworks,reject\s*$"
#    local Success="Set postfix from being used as an unrestricted mail relay, per V-72297."
#    local Failure="Failed to set postfix from being used as an unrestricted mail relay, not in compliance V-72297."#

#    echo
#    postconf -e 'smtpd_client_restrictions = permit_mynetworks,reject'
#    (postconf -n smtpd_client_restrictions | grep -E -q "$Regex1" && echo "$Success") || { echo "$Failure" ; exit 1; }
#}

#Set OS to not perform packet forwarding unless system is a router, V-72309
#function V72309 () {
#    local Regex1="^(\s*)#net.ipv4.ip_forward\s+\S+(\s*#.*)?\s*$"
#    local Regex2="s/^(\s*)#net.ipv4.ip_forward\s+\S+(\s*#.*)?\s*$/\net.ipv4.ip_forward = 0\2/"
#    local Regex3="^(\s*)net.ipv4.ip_forward\s+\S+(\s*#.*)?\s*$"
#    local Regex4="s/^(\s*)net.ipv4.ip_forward\s+\S+(\s*#.*)?\s*$/\net.ipv4.ip_forward = 0\2/"
#    local Regex5="^(\s*)net.ipv4.ip_forward\s*=\s*0?\s*$"
#    local Success="Set system to not perform package forwarding, per V-72309."
#    local Failure="Failed to set system to not perform package forwarding, not in compliance V-72309."

#    echo
#    ( (grep -E -q "$Regex1" /etc/sysctl.conf && sed -ri "$Regex2" /etc/sysctl.conf) || (grep -E -q "$Regex3" /etc/sysctl.conf && sed -ri "$Regex4" /etc/sysctl.conf) ) || echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf
#    (grep -E -q "$Regex5" /etc/sysctl.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
#}

#Set OS to not perform packet forwarding unless system is a router, V-72319
#function V72319 () {
 #   local Regex1="^(\s*)#net.ipv6.conf.all.accept_source_route\s+\S+(\s*#.*)?\s*$"
 #   local Regex2="s/^(\s*)#net.ipv6.conf.all.accept_source_route\s+\S+(\s*#.*)?\s*$/\net.ipv6.conf.all.accept_source_route = 0\2/"
 #   local Regex3="^(\s*)net.ipv6.conf.all.accept_source_route\s+\S+(\s*#.*)?\s*$"
 #   local Regex4="s/^(\s*)net.ipv6.conf.all.accept_source_route\s+\S+(\s*#.*)?\s*$/\net.ipv6.conf.all.accept_source_route = 0\2/"
 #   local Regex5="^(\s*)net.ipv6.conf.all.accept_source_route\s*=\s*0?\s*$"
 #   local Success="Set system to not accept IPv6 source-routed packets, per V-72319."
 #   local Failure="Failed to set system to not accept IPv6 source-routed packets, not in compliance V-72319."

 #   echo
 #   ( (grep -E -q "$Regex1" /etc/sysctl.conf && sed -ri "$Regex2" /etc/sysctl.conf) || (grep -E -q "$Regex3" /etc/sysctl.conf && sed -ri "$Regex4" /etc/sysctl.conf) ) || echo "net.ipv6.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
 #   (grep -E -q "$Regex5" /etc/sysctl.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
#}

#Set audit to audit all account creations, modifications, disabling, and termination events that affect "/etc/group", V-73165
#function V73165 () {
#    local Regex1="^\s*-w\s+/etc/group\s+-p\s+wa\s+-k\s+identity\s*(#.*)?$"
#    local Success="Set to enable auditing of all account creations, modifications, disabling, and termination events the affect '/etc/group', per V-73165."
#    local Failure="Failed to enable auditing of all account creations, modifications, disabling, and termination events the affect '/etc/group', not in compliance V-73165."

#    echo
#    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-w /etc/group -p wa -k identity" >> /etc/audit/rules.d/audit.rules
#    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success") || { echo "$Failure" ; exit 1; }
#}

#Set audit to audit all account creations, modifications, disabling, and termination events that affect "/etc/shadow", V-73167#
#function V73167 () {
#    local Regex1="^\s*-w\s+/etc/shadow\s+-p\s+wa\s+-k\s+identity\s*(#.*)?$"
#    local Success="Set to enable auditing of all account creations, modifications, disabling, and termination events the affect '/etc/shadow', per V-73167."
#    local Failure="Failed to enable auditing of all account creations, modifications, disabling, and termination events the affect '/etc/shadow', not in compliance V-73167."

#    echo
#    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-w /etc/shadow -p wa -k identity" >> /etc/audit/rules.d/audit.rules
#    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success") || { echo "$Failure" ; exit 1; }
#}

#Set audit to audit all account creations, modifications, disabling, and termination events that affect "/etc/opasswd", V-73173
#function V73173 () {
#    local Regex1="^\s*-w\s+/etc/security/opasswd\s+-p\s+wa\s+-k\s+identity\s*(#.*)?$"
#    local Success="Set to enable auditing of all account creations, modifications, disabling, and termination events the affect '/etc/opasswd', per V-73173."
#    local Failure="Failed to enable auditing of all account creations, modifications, disabling, and termination events the affect '/etc/opasswd', not in compliance V-73173."

#    echo
#    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-w /etc/security/opasswd -p wa -k identity" >> /etc/audit/rules.d/audit.rules
#    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success") || { echo "$Failure" ; exit 1; }
#}

#Set OS to ignore ICMP redirects, V-73175
#function V73175 () {
#    local Regex1="^(\s*)#net.ipv4.conf.all.accept_redirects\s+\S+(\s*#.*)?\s*$"
#    local Regex2="s/^(\s*)#net.ipv4.conf.all.accept_redirects\s+\S+(\s*#.*)?\s*$/\net.ipv4.conf.all.accept_redirects = 0\2/"
#    local Regex3="^(\s*)net.ipv4.conf.all.accept_redirects\s+\S+(\s*#.*)?\s*$"
#    local Regex4="s/^(\s*)net.ipv4.conf.all.accept_redirects\s+\S+(\s*#.*)?\s*$/\net.ipv4.conf.all.accept_redirects = 0\2/"
#    local Regex5="^(\s*)net.ipv4.conf.all.accept_redirects\s*=\s*0?\s*$"
#    local Success="Set system to ignore IPv4 ICMP redirect messages, per V-73175."
#    local Failure="Failed to set system to ignore IPv4 ICMP redirect messages, not in compliance V-73175."

#    echo
#    ( (grep -E -q "$Regex1" /etc/sysctl.conf && sed -ri "$Regex2" /etc/sysctl.conf) || (grep -E -q "$Regex3" /etc/sysctl.conf && sed -ri "$Regex4" /etc/sysctl.conf) ) || echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
#    (grep -E -q "$Regex5" /etc/sysctl.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
#}

#Disable DCCP kernel module, V-77821.
#function V77821 () {
#    local Regex1="^(\s*)#install dccp /bin/true\s+\S+(\s*#.*)?\s*$"
#    local Regex2="s/^(\s*)#install dccp /bin/true\s+\S+(\s*#.*)?\s*$/\install dccp /bin/true\2/"
#    local Regex3="^(\s*)#blacklist dccp\s+\S+(\s*#.*)?\s*$"
#    local Regex4="s/^(\s*)#blacklist dccp\s+\S+(\s*#.*)?\s*$/\blacklist dccp\2/"
#    local Regex5="^(\s*)install\s*dccp\s*/bin/true?\s*$"
#    local Regex6="^(\s*)blacklist\s*dccp?\s*$"
#    local Success="Disabled DCCP on the system, per V-77821."
#    local Failure="Failed to disable DCCP on the system, not in compliance V-77821."

#    echo
#    if [ -f "/etc/modprobe.d/dccp.conf" ]
#    then
#        (grep -E -q "$Regex1" /etc/modprobe.d/dccp.conf && sed -ri "$Regex2" /etc/modprobe.d/dccp.conf) || echo "install dccp /bin/true" >> /etc/modprobe.d/dccp.conf
#    else
#        echo -e "install dccp /bin/true" >> /etc/modprobe.d/dccp.conf
#    fi

#    if [ -f "/etc/modprobe.d/blacklist.conf" ]
#    then
#        (grep -E -q "$Regex3" /etc/modprobe.d/blacklist.conf && sed -ri "$Regex4" /etc/modprobe.d/blacklist.conf) || echo "blacklist dccp" >> /etc/modprobe.d/blacklist.conf
#    else
#        echo -e "blacklist dccp" >> /etc/modprobe.d/blacklist.conf
#    fi
#    (grep -E -q "$Regex5" /etc/modprobe.d/dccp.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
#    echo
#    (grep -E -q "$Regex6" /etc/modprobe.d/blacklist.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
#}

#Set OS to use virtual address randomization, V-77825
#function V77825 () {
#    local Regex1="^(\s*)#kernel.randomize_va_space\s+\S+(\s*#.*)?\s*$"
#    local Regex2="s/^(\s*)#kernel.randomize_va_space\s+\S+(\s*#.*)?\s*$/\kernel.randomize_va_space = 2\2/"
#    local Regex3="^(\s*)kernel.randomize_va_space\s+\S+(\s*#.*)?\s*$"
#    local Regex4="s/^(\s*)kernel.randomize_va_space\s+\S+(\s*#.*)?\s*$/\kernel.randomize_va_space = 2\2/"
#    local Regex5="^(\s*)kernel.randomize_va_space\s*=\s*2?\s*$"
#    local Success="Set system to use virtual address space randomization, per V-77825."
#    local Failure="Failed to set system to use virtual address space randomization, not in compliance V-77825."

#    echo
#    ( (grep -E -q "$Regex1" /etc/sysctl.conf && sed -ri "$Regex2" /etc/sysctl.conf) || (grep -E -q "$Regex3" /etc/sysctl.conf && sed -ri "$Regex4" /etc/sysctl.conf) ) || echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
#    (grep -E -q "$Regex5" /etc/sysctl.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
#}

#Set audit to audit of successful/unsuccessful attempts to use create_module, V-78999
function V78999 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+create_module\s+-k\s+module-change\s*(#.*)?$"
    local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+create_module\s+-k\s+module-change\s*(#.*)?$"
    local Success32="Auditing of the successful/unsuccessful access attempts to use create_module on 32bit systems, per V-78999."
    local Success64="Auditing of the successful/unsuccessful access attempts to use create_module on 64bit systems, per V-78999."
    local Failure32="Failed to set the auditing of successful/unsuccessful attempts to use create_module on 32bit systems, not in compliance V-78999."
    local Failure64="Failed to set the auditing of successful/unsuccessful attempts to use create_module on 64bit systems, not in compliance V-78999."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S create_module -k module-change" >> /etc/audit/rules.d/audit.rules
    (uname -p | grep -q 'x86_64' && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S create_module -k module-change" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success32") || { echo "$Failure32" ; exit 1; }
    echo
    uname -p | grep -q 'x86_64' && (grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules && echo "$Success64" || { echo "$Failure64" ; exit 1; } )
}

#Set audit to audit of successful/unsuccessful attempts to use finit_module, V-79001
function V79001 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+finit_module\s+-k\s+module-change\s*(#.*)?$"
    local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+finit_module\s+-k\s+module-change\s*(#.*)?$"
    local Success32="Auditing of the successful/unsuccessful access attempts to use finit_module on 32bit systems, per V-79001."
    local Success64="Auditing of the successful/unsuccessful access attempts to use finit_module on 64bit systems, per V-79001."
    local Failure32="Failed to set the auditing of successful/unsuccessful attempts to use finit_module on 32bit systems, not in compliance V-79001."
    local Failure64="Failed to set the auditing of successful/unsuccessful attempts to use finit_module on 64bit systems, not in compliance V-79001."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S finit_module -k module-change" >> /etc/audit/rules.d/audit.rules
    (uname -p | grep -q 'x86_64' && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S finit_module -k module-change" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success32") || { echo "$Failure32" ; exit 1; }
    echo
    uname -p | grep -q 'x86_64' && ( (grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules && echo "$Success64") || { echo "$Failure64" ; exit 1; } )
}

#Set OS to use a reverse-path filter, V-92251
#function V92251 () {
#    local Regex1="^(\s*)#net.ipv4.conf.all.rp_filter\s+\S+(\s*#.*)?\s*$"
#    local Regex2="s/^(\s*)#net.ipv4.conf.all.rp_filter\s+\S+(\s*#.*)?\s*$/\net.ipv4.conf.all.rp_filter = 1\2/"
#    local Regex3="^(\s*)net.ipv4.conf.all.rp_filter\s+\S+(\s*#.*)?\s*$"
#    local Regex4="s/^(\s*)net.ipv4.conf.all.rp_filter\s+\S+(\s*#.*)?\s*$/\net.ipv4.conf.all.rp_filter = 1\2/"
#    local Regex5="^(\s*)net.ipv4.conf.all.rp_filter\s*=\s*1?\s*$"
#    local Success="Set system to use reverse-path filter on IPv4, per V-92251."
#    local Failure="Failed to set system to use reverse-path filter on IPv4, not in compliance V-92251."

#    echo
#    ( (grep -E -q "$Regex1" /etc/sysctl.conf && sed -ri "$Regex2" /etc/sysctl.conf) || (grep -E -q "$Regex3" /etc/sysctl.conf && sed -ri "$Regex4" /etc/sysctl.conf) ) || echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf
#    (grep -E -q "$Regex5" /etc/sysctl.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
#}

#Set OS to use a reverse-path filter, V-92253
#function V92253 () {
#    local Regex1="^(\s*)#net.ipv4.conf.default.rp_filter\s+\S+(\s*#.*)?\s*$"
#    local Regex2="s/^(\s*)#net.ipv4.conf.default.rp_filter\s+\S+(\s*#.*)?\s*$/\net.ipv4.conf.default.rp_filter = 1\2/"
#    local Regex3="^(\s*)net.ipv4.conf.default.rp_filter\s+\S+(\s*#.*)?\s*$"
#    local Regex4="s/^(\s*)net.ipv4.conf.default.rp_filter\s+\S+(\s*#.*)?\s*$/\net.ipv4.conf.default.rp_filter = 1\2/"
#    local Regex5="^(\s*)net.ipv4.conf.default.rp_filter\s*=\s*1?\s*$"
#    local Success="Set system to use reverse-path filter on IPv4 by default, per V-92251."
#    local Failure="Failed to set system to use reverse-path filter on IPv4 by default, not in compliance V-92251."

#    echo
#    ( (grep -E -q "$Regex1" /etc/sysctl.conf && sed -ri "$Regex2" /etc/sysctl.conf) || (grep -E -q "$Regex3" /etc/sysctl.conf && sed -ri "$Regex4" /etc/sysctl.conf) ) || echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf
#    (grep -E -q "$Regex5" /etc/sysctl.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
#}

#Apply all CATIIs
function Medium () {
    echo
    echo "Applying all compatible CAT IIs"
    V71899
    V71903
    V71905
    V71907
    V71909
    V71911
    V71913
    V71915
    V71917
    V71919
    V71921
    V71925
    V71935
    V71941
    V71943
    V71945
    V71933  #Placed after the stigs using authconfig to prevent them from overriding the change.
    V71951
    V71959
    V72095
    V72097
    V72099
    V72101
    V72103
    V72105
    V72107
    V72109
    V72111
    V72113
    V72115
    V72117
    V72119
    V72121
    V72123
    V72125
    V72127
    V72129
    V72131
    V72133
    V72135
    V72137
    V72139
    V72141
    V72145
    V72147
    V72149
    V72151
    V72153
    V72155
    V72157
    V72159
    V72161
    V72163
    V72165
    V72167
    V72171
    V72173
    V72175
    V72177
    V72179
    V72183
    V72185
    V72187
    V72189
    V72191
    V72197
    V72199
    V72201
    V72203
    V72205
    V72207
    V72223
    V72237
    V72241
    V72243
    V72245
    V72247
    V72249
    V72259
    V72261
    V72263
    V72267
    V72283
    V72285
    V72287
    V72289
    V72291
    V72293
    V72297
    V72309
    V72319
    V73165
    V73167
    V73173
    V73175
    V77821
    V77825
    V78999
    V79001
    V92251
    V92253
}

#------------------
#CAT I STIGS\High
#------------------

#Verify that gpgcheck is Globally Activated, V-71979
function V71979 () {
    local Regex1="^(\s*)localpkg_gpgcheck\s*=\s*\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)localpkg_gpgcheck\s*=\s*\S+(\s*#.*)?\s*$/\localpkg_gpgcheck=1\2/"
    local Regex3="^(\s*)localpkg_gpgcheck\s*=\s*1\s*$"
    local Success="Yum is now set to require certificates, per V-71979"
    local Failure="Yum was not properly set to use certificates, not in compliance with V-71979"

    echo
    (grep -E -q "$Regex1" /etc/yum.conf && sed -ri "$Regex2" /etc/yum.conf) || echo "localpkg_gpgcheck=1" >> /etc/yum.conf
    (grep -E -q "$Regex3" /etc/yum.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Disable and mask  Ctrl-Alt-Delete, V-71993
function V71993 () {
    local Success="Ctrl-Alt-Delete is disabled, per V-71993"
    local Failure="Ctrl-Alt-Delete hasn't been disabled, not in compliance with per V-71993"

    echo
    systemctl mask ctrl-alt-del.target > /dev/null
    ( (systemctl status ctrl-alt-del.target | grep -q "Loaded: masked" && systemctl status ctrl-alt-del.target | grep -q "Active: inactive") && echo "$Success")  || { echo "$Failure" ; exit 1; }
}

function High () {
    echo
    echo "Applying all CAT I STIGs that are compatible, V-71979 & V-71993"
    V71979
    V71993
}

#------------------
#Clean up
#------------------

function Cleanup () {
    echo
    (rm -rf "$StagingPath" && echo "Staging directory has been cleaned.") || echo "Failed to clean up the staging directory."
}

#Set default backup location that can be modified via argument.
BackupDIR="/etc/stigbackup"

#Setting variable for default input
Level=${1:-"High"}
StagingPath=${2:-"/var/tmp/STIG"}

Backup

#Setting script to run through all stigs if no input is detected.
if [ "$Level" =  "High" ]
then
    High
    Medium
    Low
elif [ "$Level" = "Medium" ]
then
    Medium
    Low
elif [ "$Level" = "Low" ]
then
    Low
else
    for Level in "$@"
    do
    "$Level"
    done
fi

Cleanup
echo
service auditd restart
echo
sysctl --system > /dev/null
exit 0
