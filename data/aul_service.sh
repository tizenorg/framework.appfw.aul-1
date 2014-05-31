usage()
{
	echo "--------------------------------------------------------------------------"
	echo "aul_services.sh package_name service_name1 service_name2 ... service_nameN"
	echo "--------------------------------------------------------------------------"
}

if [ -z $1 ] 
then
	echo "package name is NULL"
	usage
	exit
fi

if [ -z $2 ] 
then
	echo "service name is NULL"
	usage
	exit
fi

pkg=$1
shift
while [ "$*" != "" ]
do
	sqlite3 /opt/dbspace/.mida.db "insert into svc(pkg_name,svc_name) values ('$pkg','$1')"
	shift
done
