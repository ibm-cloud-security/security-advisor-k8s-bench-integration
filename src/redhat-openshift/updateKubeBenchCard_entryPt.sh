set -x

while true; do
    /kubebench-sa-adapter/$CLOUD_ENV/update_kubebenchcard.sh $1 $2 $3 $4 &
  sleep 3600
done