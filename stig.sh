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
