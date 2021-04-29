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


#Set audit to audit of successful/unsuccessful attempts to use kmod, V-72191
function V72191 () {
    local Regex1="^\s*-w\s+/usr/bin/kmod\s+-p\s+x\s+-F\s+auid!=4294967295\s+-k\s+module-change\s*(#.*)?$"
    local Success="Auditing of successful/unsuccessful attempts to use kmod, per V-72191."
    local Failure="Failed to set auditing of when successful/unsuccessful attempts to use kmod occur , not in compliance V-72191."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-w /usr/bin/kmod -p x -F auid!=4294967295 -k module-change" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success") || { echo "$Failure" ; exit 1; }
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
