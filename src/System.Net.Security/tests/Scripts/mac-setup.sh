host_name=`hostname`
admin_name=diradmin
admin_password=password
realm="TEST.COREFX.NET"
user_password=password
directory_path="/LDAPv3/127.0.0.1"
PROGNAME=$(basename $0)
usage()
{
    echo "This script must be run with super-user privileges."
    echo "Usage: ${PROGNAME} "
    echo "   -h to print this message"
    echo "   [-p <password for krb_user>]"
    echo "   [-a adminname]"
    echo "   [-r realm-name]"
    echo "   [-u user-name]"
    echo "   [-P password for open directory admin"]
    echo "   [-d directory </LDAPv3/127.0.0.1>"]
}

# Parse command-line arguments
ARGS=`getopt hp:P:a:r:u:d:  -- $*`
if [ $? != 0 ]
then
    usage
    exit 1
fi
set -- $ARGS

for i
do
    case "$i" in
        -h) usage; exit 0;;
        -a) admin_name="$2"; shift; shift;;
        -r) realm="$2"; shift; shift;;
        -p) user_password="$2"; shift; shift;;
        -d) directory_path="$2"; shift; shift;;
        -P) admin_password="$2"; shift; shift;;
        --) shift;
    esac
done

#Compute the  UID for the user

maxid=$(dscl ${directory_path} -list /Users UniqueID | awk '{print $2}' | sort -ug | tail -1)
newid=$((maxid+1))

echo "User password = ${user_password}"
echo "Admin password = ${admin_password}"
echo "New Id = ${newid}"
echo "directory_path = ${directory_path}"

host_principal="HOST/${host_name}@${realm}"
http_principal="HTTP/${host_name}@${realm}"

echo "Creating ${host_principal} "
krbservicesetup -r ${realm} -a ${admin_name} -p ${admin_password} -x HOST ${host_principal}

echo "Creating ${http_principal} "
krbservicesetup -r ${realm} -a ${admin_name} -p ${admin_password} -x HTTP ${http_principal}

echo "Creating krb_user"
krbservicesetup -t ${realm} -a ${admin_name} -p ${admin_password} krb_user

#Creating user
dscl ${directory_path} -create /Users/krb_user
dscl ${directory_path} -create /Users/krb_user
dscl ${directory_path} -create /Users/krb_user HomeDirectoryQuota 0
dscl ${directory_path} -create /Users/krb_user RealName "KRB USER"
dscl ${directory_path} -create /Users/krb_user UniqueID $newid
dscl ${directory_path} -create /Users/krb_user PrimaryGroupID 20 # TODO: verify for other machines
dscl ${directory_path} -create /Users/krb_user NFSHomeDirectory /dev/null
dscl ${directory_path} -passwd /Users/krb_user ${user_password}
