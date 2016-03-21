host_name=`hostname`
admin_name=diradmin
admin_password=password
realm="TEST.COREFX.NET"
user_password=password
directory_path="/LDAPv3/127.0.0.1"
PROGNAME=$(basename $0)
krbuser="krb_user"
usage()
{
    echo "This script must be run with super-user privileges."
    echo "Usage: ${PROGNAME} "
    echo "   -h to print this message"
    echo "   [-p <password for ${krbuser}>]"
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

host_principal="TESTHOST/${host_name}@${realm}"
http_principal="TESTHTTP/${host_name}@${realm}"

echo "Creating ${host_principal} "
krbservicesetup -r ${realm} -a ${admin_name} -p ${admin_password} -x HOST ${host_principal}

echo "Creating ${http_principal} "
krbservicesetup -r ${realm} -a ${admin_name} -p ${admin_password} -x HTTP ${http_principal}

#Creating user
dscl -u ${admin_name} -P ${admin_password} ${directory_path} -create /Users/${krbuser}
dscl -u ${admin_name} -P ${admin_password} ${directory_path} -create /Users/${krbuser}
dscl -u ${admin_name} -P ${admin_password} ${directory_path} -create /Users/${krbuser} HomeDirectoryQuota 0
dscl -u ${admin_name} -P ${admin_password} ${directory_path} -create /Users/${krbuser} RealName "KRB USER"
dscl -u ${admin_name} -P ${admin_password} ${directory_path} -create /Users/${krbuser} UniqueID $newid
dscl -u ${admin_name} -P ${admin_password} ${directory_path} -create /Users/${krbuser} PrimaryGroupID 20 # TODO: verify for other machines
dscl -u ${admin_name} -P ${admin_password} ${directory_path} -create /Users/${krbuser} NFSHomeDirectory /dev/null
dscl -u ${admin_name} -P ${admin_password} ${directory_path} -passwd /Users/${krbuser} ${user_password}
