# ldapwhois

ldapwhois() {
    local ldapUser="$1"

    # Determine if input is a username or a name
    if [[ "$ldapUser" =~ ^[a-zA-Z]+[[:space:]]?[a-zA-Z]*$ ]]; then
        # Assume it's a name (full name or single name)
        local searchFilter="(&(objectClass=user)(displayName=*${ldapUser}*))"
        local searchAttribute="userPrincipalName givenName"
    else
        # Assume input is a username
        ldapUser="${ldapUser%%@*}@vetinst.no"
        local searchFilter="(&(objectClass=user)(userPrincipalName=${ldapUser}))"
        local searchAttribute="displayName"
    fi

    # Extract viXXXX part for kinit
    local principal="${USER}@VETINST.NO"

    # Check for valid Kerberos ticket
    if ! klist -s; then
        echo "No valid Kerberos ticket found. Please run: kinit \"$principal\""
        return 1
    fi  

    # Perform LDAP search
    ldapsearch -LLL -Q -H ldap://dc02.vetinst.no:3268 -Y GSSAPI -b dc=vetinst,dc=no "$searchFilter" $searchAttribute | awk '/::/ {split($0, a, ":: "); cmd = "echo " a[2] " | base64 -d"; cmd | getline decoded; print a[1] ": " decoded "\n"; close(cmd); next} {print $0}'

}

ldapwho() { ldapwhois "$@"; }
