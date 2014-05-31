usage()
{
	echo "----------------------------------------------------------"
	echo "aul_mime.sh package_name mimetype1 mimetype2 ... mimetypeN"
	echo "----------------------------------------------------------"
}

if [ -z $1 ] 
then
	echo "package name is NULL"
	usage
	exit
fi

if [ -z $2 ] 
then
	echo "mimetype is NULL"
	usage
	exit
fi

pkg=$1
shift
while [ "$*" != "" ]
do
	sqlite3 /opt/dbspace/.mida.db "insert into mida(pkg_name,mime_type) values ('$pkg','$1')"
	shift
done
